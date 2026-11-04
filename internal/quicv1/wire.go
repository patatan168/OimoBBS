// Package quicv1 はRFC9000のサーバー側QUIC v1を実装する。暗号primitiveとTLSは標準実装を使う。
package quicv1

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const maxVarint = uint64(1<<62 - 1)

var errWire = errors.New("invalid QUIC wire data")

// appendVarint はRFC9000の整数を最短表現で追加する。範囲外は内部不変条件違反。
func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(dst, byte(v))
	case v < 16384:
		return binary.BigEndian.AppendUint16(dst, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(dst, uint32(v)|0x80000000)
	case v <= maxVarint:
		return binary.BigEndian.AppendUint64(dst, v|0xc000000000000000)
	default:
		panic("QUIC varint overflow")
	}
}

// wireReader は受信byteを借り、長さ検査後だけ位置を進める。
type wireReader struct {
	data []byte
	pos  int
}

func (r *wireReader) left() int { return len(r.data) - r.pos }
func (r *wireReader) take(n int) ([]byte, error) {
	if n < 0 || n > r.left() {
		return nil, errWire
	}
	p := r.data[r.pos : r.pos+n]
	r.pos += n
	return p, nil
}
func (r *wireReader) integer() (uint64, error) {
	if r.left() == 0 {
		return 0, errWire
	}
	n := 1 << int(r.data[r.pos]>>6)
	p, err := r.take(n)
	if err != nil {
		return 0, err
	}
	v := uint64(p[0] & 63)
	for _, b := range p[1:] {
		v = v<<8 | uint64(b)
	}
	return v, nil
}
func (r *wireReader) blob() ([]byte, error) {
	n, err := r.integer()
	if err != nil || n > uint64(r.left()) {
		return nil, errWire
	}
	return r.take(int(n))
}

// transportError はpeerへ通知できる固定codeと内部診断用の説明を分ける。
type transportError struct {
	code, frame uint64
	reason      string
}

func (e *transportError) Error() string {
	return fmt.Sprintf("QUIC transport %x (frame %x): %s", e.code, e.frame, e.reason)
}
func protocolError(code, frame uint64, reason string) error {
	return &transportError{code, frame, reason}
}

// packetNumber はtruncated番号を、次に期待する番号へ最も近い値に復元する。
func packetNumber(truncated uint64, n int, expected uint64) uint64 {
	window := uint64(1) << (8 * n)
	half := window / 2
	candidate := (expected &^ (window - 1)) | truncated
	if candidate+half <= expected && candidate < maxVarint-window {
		return candidate + window
	}
	if candidate > expected+half && candidate >= window {
		return candidate - window
	}
	return candidate
}
