// HTTP/3 frameの長さを先に検証し、可変長整数と未知frameの読み飛ばしを有界にする。
package http3native

import (
	"encoding/binary"
	"errors"
	"io"
)

func integer(v uint64) []byte {
	return appendInteger(nil, v)
}

func appendInteger(dst []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(dst, byte(v))
	case v < 16384:
		return binary.BigEndian.AppendUint16(dst, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(dst, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(dst, v|1<<62|1<<63)
	}
}
func readInteger(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:1]); err != nil {
		return 0, err
	}
	n := 1 << (b[0] >> 6)
	b[0] &= 63
	if _, err := io.ReadFull(r, b[1:n]); err != nil {
		return 0, io.ErrUnexpectedEOF
	}
	v := uint64(b[0])
	for _, x := range b[1:n] {
		v = v<<8 | uint64(x)
	}
	return v, nil
}
func frame(kind uint64, data []byte) []byte {
	b := integer(kind)
	b = append(b, integer(uint64(len(data)))...)
	return append(b, data...)
}
func readFrame(r io.Reader) (kind, size uint64, err error) {
	kind, err = readInteger(r)
	if err != nil {
		return
	}
	size, err = readInteger(r)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}
func bounded(r io.Reader, n uint64, limit uint64) ([]byte, error) {
	if n > limit {
		return nil, errors.New("HTTP/3 frame budget")
	}
	data := make([]byte, int(n))
	_, err := io.ReadFull(r, data)
	return data, err
}

// chargeFraming は最大16byteのframe headerも数え、空DATAや未知frameの反復を制限する。
// DATA本文はhandlerの本文上限が数え、それ以外のpayloadはこの16KiB枠へ含める。
func chargeFraming(used *uint64, payload uint64) error {
	const limit = 16 << 10
	if payload > limit-16 || *used > limit-16-payload {
		return &connectionError{errExcessive}
	}
	*used += 16 + payload
	return nil
}

// forbiddenRequestFrame は制御専用frameとHTTP/2用の予約frameを要求から排除する。
// 未知の拡張frameは読み飛ばし、RFC9114で禁止された番号だけを拒否する。
func forbiddenRequestFrame(kind uint64) bool {
	switch kind {
	case 2, 3, 4, 5, 6, 7, 8, 9, 0xd:
		return true
	}
	return false
}
