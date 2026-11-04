// QUIC v1のlong/short headerを有界に解析し、packet番号空間を識別する。
package quicv1

import (
	"encoding/binary"
)

const (
	spaceInitial = iota
	spaceHandshake
	spaceApplication
)
const connectionIDSize = 8

type packetHeader struct {
	space             int
	dcid, scid, token []byte
	pnOffset, size    int
	version           uint32
	retry             bool
}

func parseHeader(data []byte) (packetHeader, error) {
	h := packetHeader{space: spaceApplication, size: len(data), version: 1}
	if len(data) < 1 || data[0]&0x40 == 0 {
		return h, errWire
	}
	if data[0]&0x80 == 0 {
		if len(data) < 1+connectionIDSize {
			return h, errWire
		}
		h.dcid = data[1 : 1+connectionIDSize]
		h.pnOffset = 1 + connectionIDSize
		return h, nil
	}
	if len(data) < 7 {
		return h, errWire
	}
	h.version = binary.BigEndian.Uint32(data[1:5])
	r := wireReader{data: data, pos: 5}
	n, _ := r.take(1)
	if n[0] > 20 {
		return h, errWire
	}
	var err error
	h.dcid, err = r.take(int(n[0]))
	if err != nil {
		return h, err
	}
	n, err = r.take(1)
	if err != nil || n[0] > 20 {
		return h, errWire
	}
	h.scid, err = r.take(int(n[0]))
	if err != nil {
		return h, err
	}
	if h.version != 1 {
		h.pnOffset = r.pos
		return h, nil
	}
	switch (data[0] >> 4) & 3 {
	case 0:
		h.space = spaceInitial
		h.token, err = r.blob()
		if err != nil {
			return h, err
		}
	case 1:
		return h, errWire // 0-RTTを受理しない。
	case 2:
		h.space = spaceHandshake
	case 3:
		h.retry = true
		return h, nil
	}
	length, err := r.integer()
	if err != nil || length > uint64(r.left()) || length < 17 {
		return h, errWire
	}
	h.pnOffset = r.pos
	h.size = r.pos + int(length)
	return h, nil
}

func makePacketHeader(space int, dcid, scid []byte, pn uint64, payloadLen int, keyPhase bool, pnSize int) ([]byte, int) {
	return appendPacketHeader(nil, space, dcid, scid, pn, payloadLen, keyPhase, pnSize)
}

// appendPacketHeader は送信actorの作業bufferへheaderを構築する。
func appendPacketHeader(dst []byte, space int, dcid, scid []byte, pn uint64, payloadLen int, keyPhase bool, pnSize int) ([]byte, int) {
	// 最小2-byteのpacket番号を使い、未ACK範囲が広い場合は4-byteへ戻す。
	if space == spaceApplication {
		first := byte(0x40 | byte(pnSize-1))
		if keyPhase {
			first |= 4
		}
		out := append(dst, first)
		out = append(out, dcid...)
		offset := len(out)
		if pnSize == 2 {
			out = binary.BigEndian.AppendUint16(out, uint16(pn))
		} else {
			out = binary.BigEndian.AppendUint32(out, uint32(pn))
		}
		return out, offset
	}
	first := byte(0xc0 | byte(pnSize-1))
	if space == spaceHandshake {
		first = 0xe0 | byte(pnSize-1)
	}
	out := binary.BigEndian.AppendUint32(append(dst, first), 1)
	out = append(out, byte(len(dcid)))
	out = append(out, dcid...)
	out = append(out, byte(len(scid)))
	out = append(out, scid...)
	if space == spaceInitial {
		out = append(out, 0)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(payloadLen+pnSize+16)|0x4000)
	offset := len(out)
	if pnSize == 2 {
		out = binary.BigEndian.AppendUint16(out, uint16(pn))
	} else {
		out = binary.BigEndian.AppendUint32(out, uint32(pn))
	}
	return out, offset
}
