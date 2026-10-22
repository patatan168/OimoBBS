// Package store は長さ制限付きの永続フレームを扱う。業務操作の検証は上位層の責務。
package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

const (
	HeaderSize       = 64
	MaxFrameBody     = 8 << 20
	MaxOperationJSON = 1 << 20
	MaxOperationDAT  = 4 << 20
)

var le = binary.LittleEndian
var crcTable = crc32.MakeTable(crc32.Castagnoli)
var ErrCorrupt = errors.New("corrupt storage")
var ErrIncomplete = errors.New("incomplete tail")

func checksum(b []byte) uint32 { return crc32.Checksum(b, crcTable) }

// Header はthread(kind=0)またはcontrol(kind=1..9)WALの所有境界。
type Header struct {
	Kind                     uint16
	Owner                    domain.ID
	Key, BaseSeq, Generation uint64
}

// EncodeHeader は設計11/13の64byteヘッダを生成する。
func EncodeHeader(h Header) ([]byte, error) {
	if h.Owner == (domain.ID{}) || h.Generation == 0 || h.Kind > 9 || h.Kind == 0 && h.Key == 0 {
		return nil, ErrCorrupt
	}
	b := make([]byte, 64)
	copy(b, "OIMOWAL2")
	if h.Kind != 0 {
		copy(b, "OIMOCTL2")
		le.PutUint16(b[12:], h.Kind)
	}
	le.PutUint16(b[8:], 2)
	le.PutUint16(b[10:], 64)
	copy(b[16:], h.Owner[:])
	le.PutUint64(b[32:], h.Key)
	le.PutUint64(b[40:], h.BaseSeq)
	le.PutUint64(b[48:], h.Generation)
	le.PutUint32(b[60:], checksum(b[:60]))
	return b, nil
}

// DecodeHeader は未知形式、CRC、予約領域、所有境界を検査する。
func DecodeHeader(b []byte) (Header, error) {
	var h Header
	if len(b) != 64 || le.Uint16(b[8:]) != 2 || le.Uint16(b[10:]) != 64 || le.Uint32(b[56:]) != 0 || le.Uint32(b[60:]) != checksum(b[:60]) {
		return h, ErrCorrupt
	}
	switch string(b[:8]) {
	case "OIMOWAL2":
		if le.Uint32(b[12:]) != 0 {
			return h, ErrCorrupt
		}
	case "OIMOCTL2":
		h.Kind = le.Uint16(b[12:])
		if h.Kind < 1 || h.Kind > 9 || le.Uint16(b[14:]) != 0 {
			return h, ErrCorrupt
		}
	default:
		return h, ErrCorrupt
	}
	copy(h.Owner[:], b[16:32])
	h.Key = le.Uint64(b[32:])
	h.BaseSeq = le.Uint64(b[40:])
	h.Generation = le.Uint64(b[48:])
	if _, e := EncodeHeader(h); e != nil {
		return Header{}, e
	}
	return h, nil
}

// Record は操作IDと検証前の業務JSON・固定DATバイトを保持する。
type Record struct {
	ID        domain.ID
	JSON, DAT []byte
}
type Frame struct {
	FirstSeq uint64
	Records  []Record
}

func validateFrame(f Frame) error {
	if f.FirstSeq == 0 || len(f.Records) < 1 || len(f.Records) > 32 || uint64(len(f.Records)-1) > math.MaxUint64-f.FirstSeq {
		return ErrCorrupt
	}
	ids := map[domain.ID]bool{}
	for _, r := range f.Records {
		if r.ID == (domain.ID{}) || ids[r.ID] || len(r.JSON) < 2 || len(r.JSON) > MaxOperationJSON || len(r.DAT) > MaxOperationDAT {
			return ErrCorrupt
		}
		ids[r.ID] = true
		if e := strictjson.Validate(r.JSON); e != nil {
			return fmt.Errorf("%w: operation JSON", ErrCorrupt)
		}
	}
	return nil
}

// EncodeFrame は長さと本体を別々にCRC保護する。
func EncodeFrame(f Frame) ([]byte, error) {
	if e := validateFrame(f); e != nil {
		return nil, e
	}
	n := 12
	for _, r := range f.Records {
		n += 24 + len(r.JSON) + len(r.DAT)
	}
	if n > MaxFrameBody {
		return nil, ErrCorrupt
	}
	b := make([]byte, n+20)
	le.PutUint32(b, uint32(n))
	le.PutUint32(b[4:], checksum(b[:4]))
	le.PutUint64(b[8:], f.FirstSeq)
	le.PutUint32(b[16:], uint32(len(f.Records)))
	pos := 20
	for _, r := range f.Records {
		copy(b[pos:], r.ID[:])
		pos += 16
		le.PutUint32(b[pos:], uint32(len(r.JSON)))
		pos += 4
		copy(b[pos:], r.JSON)
		pos += len(r.JSON)
		le.PutUint32(b[pos:], uint32(len(r.DAT)))
		pos += 4
		copy(b[pos:], r.DAT)
		pos += len(r.DAT)
	}
	le.PutUint32(b[8+n:], checksum(b[8:8+n]))
	copy(b[12+n:], "OIMOEND1")
	return b, nil
}

// ReadFrame は正常EOF・不完全末尾・完全な破損を区別する。破損を切捨てない。
func ReadFrame(r io.Reader) (Frame, int64, error) {
	var f Frame
	prefix := make([]byte, 8)
	n, e := io.ReadFull(r, prefix)
	if e == io.EOF && n == 0 {
		return f, 0, io.EOF
	}
	if e == io.EOF || e == io.ErrUnexpectedEOF {
		return f, int64(n), ErrIncomplete
	}
	if e != nil {
		return f, int64(n), e
	}
	length := le.Uint32(prefix)
	if checksum(prefix[:4]) != le.Uint32(prefix[4:]) || length < 38 || length > MaxFrameBody {
		return f, 8, ErrCorrupt
	}
	body := make([]byte, int(length)+12)
	n, e = io.ReadFull(r, body)
	size := int64(n) + 8
	if e == io.EOF || e == io.ErrUnexpectedEOF {
		return f, size, ErrIncomplete
	}
	if e != nil {
		return f, size, e
	}
	if checksum(body[:length]) != le.Uint32(body[length:]) || string(body[length+4:]) != "OIMOEND1" {
		return f, size, ErrCorrupt
	}
	f, e = decodeBody(body[:length])
	return f, size, e
}

// decodeFrameView は呼出中に変更されない完成byteを参照して全構造・CRC・JSONを検査する。
// 結果を外へ渡す場合は複製する。ストリームのReadFrameは専有bufferから同じ検査を行う。
func decodeFrameView(raw []byte) (Frame, error) {
	if len(raw) < 8 {
		return Frame{}, ErrCorrupt
	}
	length := le.Uint32(raw)
	if checksum(raw[:4]) != le.Uint32(raw[4:]) || length < 38 || length > MaxFrameBody || uint64(length)+20 != uint64(len(raw)) {
		return Frame{}, ErrCorrupt
	}
	body := raw[8:]
	if checksum(body[:length]) != le.Uint32(body[length:]) || string(body[length+4:]) != "OIMOEND1" {
		return Frame{}, ErrCorrupt
	}
	return decodeBody(body[:length])
}

func decodeBody(b []byte) (Frame, error) {
	f := Frame{FirstSeq: le.Uint64(b)}
	count := le.Uint32(b[8:])
	if count < 1 || count > 32 {
		return Frame{}, ErrCorrupt
	}
	b = b[12:]
	for range count {
		if len(b) < 24 {
			return Frame{}, ErrCorrupt
		}
		var r Record
		copy(r.ID[:], b[:16])
		n := le.Uint32(b[16:])
		b = b[20:]
		if n < 2 || n > MaxOperationJSON || uint64(n)+4 > uint64(len(b)) {
			return Frame{}, ErrCorrupt
		}
		r.JSON = b[:n:n]
		b = b[n:]
		n = le.Uint32(b)
		b = b[4:]
		if n > MaxOperationDAT || uint64(n) > uint64(len(b)) {
			return Frame{}, ErrCorrupt
		}
		r.DAT = b[:n:n]
		b = b[n:]
		f.Records = append(f.Records, r)
	}
	if len(b) != 0 {
		return Frame{}, ErrCorrupt
	}
	return f, validateFrame(f)
}
