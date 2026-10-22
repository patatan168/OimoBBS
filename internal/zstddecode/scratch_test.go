// frame内のliteral作業領域が再利用され、raw literalと混同されないことを検査する。
package zstddecode

import (
	"bytes"
	"reflect"
	"testing"

	"oimobbs/internal/testutil"
	"oimobbs/internal/zstdencode"
)

func TestHuffmanTableScratchOverwrite(t *testing.T) {
	var scratch [2048]huffmanCell
	for i := range scratch {
		scratch[i] = huffmanCell{255, 255}
	}
	for _, data := range [][]byte{{130, 0x11, 0x10}, {128, 0x10}, {130, 0x11, 0x10}} {
		table, depth, used, err := huffmanTable(data, scratch[:])
		if err != nil || &table[0] != &scratch[0] || len(table) != 1<<uint(depth) || used != len(data) {
			t.Fatal("table scratch not reused", depth, used, err)
		}
		for symbol, cell := range table {
			if cell != (huffmanCell{byte(symbol), uint8(depth)}) {
				t.Fatal("stale table cell", symbol, cell)
			}
		}
	}
	before := scratch
	if table, _, _, err := huffmanTable([]byte{128}, scratch[:]); err == nil || table != nil || !reflect.DeepEqual(before, scratch) {
		t.Fatal("invalid weights reused stale table")
	}
}

func TestLiteralScratchReuseAndRawIsolation(t *testing.T) {
	var encoder zstdencode.Encoder
	frame := encoder.Encode(testutil.DATFixture("entropy"))
	// このfixtureは4byte内容長のsingle-segment frame。最初の圧縮blockを取り出す。
	if frame[4] != 0xa0 || frame[9]>>1&3 != 2 {
		t.Fatal("fixture requires a compressed block")
	}
	length := (int(frame[9]) | int(frame[10])<<8 | int(frame[11])<<16) >> 3
	payload := frame[12 : 12+length]
	if payload[0]&15 != 14 {
		t.Fatal("fixture requires Huffman literals")
	}
	var scratch []byte
	first, used, err := decodeLiterals(payload, &scratch)
	if err != nil || len(first) == 0 || cap(scratch) < len(first) {
		t.Fatal("initial literals", used, err)
	}
	want := bytes.Clone(first)
	backing := &scratch[:cap(scratch)][0]
	for i := range first {
		first[i] = 0xaa
	}
	second, nextUsed, err := decodeLiterals(payload, &scratch)
	if err != nil || used != nextUsed || !bytes.Equal(second, want) || &second[0] != backing {
		t.Fatal("literal scratch was not reused correctly", err)
	}
	// raw literalは入力を参照するが、次の圧縮block用scratchを置換しない。
	raw := []byte{0x3c, 0, 0, 'a', 'b', 'c'}
	got, rawUsed, err := decodeLiterals(raw, &scratch)
	if err != nil || rawUsed != len(raw) || string(got) != "abc" || &scratch[:cap(scratch)][0] != backing || !bytes.Equal(second, want) {
		t.Fatal("raw literal replaced or modified scratch", err)
	}
	if got, _, err := decodeLiterals(payload[:5], &scratch); err == nil || got != nil {
		t.Fatal("truncated literal accepted")
	}
}
