// 定義済みFSE表の全長さcodeと配信offset範囲を独立復号器で検証する。
package zstdencode

import (
	"bytes"
	"fmt"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstddecode"
	"testing"
)

// TestPredefinedCodeFrames は各列の全codeを、他の列と組み合わせた単一参照frameで照合する。
func TestPredefinedCodeFrames(t *testing.T) {
	for _, column := range []int{0, 1, 2} {
		maximum := []int{35, 20, 52}[column]
		for code := 0; code <= maximum; code++ {
			t.Run(fmt.Sprintf("%d/%d", column, code), func(t *testing.T) {
				ll, ml, oc := 1, 3, 0
				if column == 0 {
					for {
						symbol, _, _ := literalLength(ll)
						if symbol == code {
							break
						}
						ll++
						if code == 0 {
							ll = 0
							break
						}
					}
				} else if column == 2 {
					for {
						symbol, _, _ := matchLengthCode(ml)
						if symbol == code {
							break
						}
						ml++
					}
				} else {
					oc = code
				}
				assertPredefinedFrame(t, ll, ml, oc)
			})
		}
	}
}

// assertPredefinedFrame は3列すべて定義済みのframeを作り、本文・厳密な終端・出力上限を確認する。
func assertPredefinedFrame(t *testing.T, ll, ml, oc int) {
	t.Helper()
	distance := 1 << uint(oc)
	if distance <= 3 {
		distance = []int{1, 4}[oc]
		if ll == 0 {
			distance = 4
		}
	} else {
		distance -= 3
	}
	history := max(16, distance-ll)
	raw := bytes.Repeat([]byte{'a'}, history+ll+ml)
	var e Encoder
	e.smallHTTP, e.optimizeEntropy = true, true
	e.literals = raw[history : history+ll]
	lc, lw, le := literalLength(ll)
	mc, mw, me := matchLengthCode(ml)
	e.coded = []sequenceCode{{symbol: [3]uint8{uint8(lc), uint8(oc), uint8(mc)}, width: uint8(lw + mw + uint(oc)), extra: uint64(le) | uint64(me)<<lw}}
	for column, symbol := range e.coded[0].symbol {
		e.counts[column][symbol]++
	}
	payload, _ := e.block([3]int{1, 4, 8})
	at := rawLiteralHeaderSize(ll) + ll
	if payload[at] != 1 || payload[at+1] != 0 {
		t.Fatal("predefined tables not selected", payload[at:at+2])
	}
	frame := frameHeader(nil, uint64(len(raw)))
	for begin := 0; begin < history; begin += blockLimit {
		end := min(begin+blockLimit, history)
		header := uint32(end-begin) << 3
		frame = append(frame, byte(header), byte(header>>8), byte(header>>16))
		frame = append(frame, raw[begin:end]...)
	}
	header := uint32(len(payload))<<3 | 5
	frame = append(frame, byte(header), byte(header>>8), byte(header>>16))
	frame = append(frame, payload...)
	independent, err := testutil.DecodeZstd(frame)
	if err != nil || !bytes.Equal(independent, raw) {
		t.Fatal("independent decode", err)
	}
	decoded, err := zstddecode.Decode(frame, len(raw))
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatal("product decode", err)
	}
	for _, bad := range [][]byte{frame[:len(frame)-1], append(bytes.Clone(frame), 0)} {
		if partial, err := zstddecode.Decode(bad, len(raw)); err == nil || partial != nil {
			t.Fatal("bad ending accepted")
		}
	}
	if _, err := zstddecode.Decode(frame, len(raw)-1); err == nil {
		t.Fatal("size mismatch accepted")
	}
}
