// 単一参照で表された短い周期を調べ、同じbyteだけのblockを見つける。
package zstdencode

import (
	"bytes"
	"encoding/binary"
)

// isRLEBlock は探索済みの列から周期8byte以下の一様なblockを判定する。
// literalが先頭の0〜1byteだけなら、周期と先頭literalの計9byte以内を調べれば足りる。
// block全体の再走査と符号表の構築を省く。直前にparseした本文を渡すこと。
func (e *Encoder) isRLEBlock(body []byte) bool {
	if len(body) < 2 || len(e.coded) != 1 || len(e.literals) > 1 {
		return false
	}
	literal := len(e.literals)
	if int(e.coded[0].symbol[0]) != literal {
		return false
	}
	period := e.nextRepeats[0]
	if period < 1 || period > 8 {
		return false
	}
	for _, v := range body[1:min(len(body), period+literal)] {
		if v != body[0] {
			return false
		}
	}
	return true
}

// uniformFrame は確認済みの一様な本文を、従来のparseと同じblock列で返す。
// 先頭blockは17byte以上。末尾が16byte未満なら参照を採らない既存動作に合わせrawにする。
func (e *Encoder) uniformFrame(body []byte) []byte {
	out := frameHeader(e.frameBuffer[:0], uint64(len(body)))
	for begin := 0; begin < len(body); begin += blockLimit {
		end := min(begin+blockLimit, len(body))
		size := end - begin
		kind, payload := uint32(1), body[begin:begin+1]
		if size < 16 {
			kind, payload = 0, body[begin:end]
		}
		header := uint32(size)<<3 | kind<<1
		if end == len(body) {
			header |= 1
		}
		out = append(out, byte(header), byte(header>>8), byte(header>>16))
		out = append(out, payload...)
	}
	e.frameBuffer = out
	return out
}

// uniformBody は先頭wordで通常入力を除き、一様に見える本文だけ全体を確認する。
// 16byte以下の先頭blockは既存の参照費用判定でRLEにならないため対象外。
func uniformBody(body []byte) bool {
	return len(body) >= 17 && binary.LittleEndian.Uint64(body[:8]) == uint64(body[0])*0x0101010101010101 && bytes.Count(body, body[:1]) == len(body)
}
