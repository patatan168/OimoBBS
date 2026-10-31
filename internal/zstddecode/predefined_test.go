// 定義済みFSEの既知状態と、すべての表内遷移・共有表の非破壊を検査する。
package zstddecode

import (
	"reflect"
	"testing"
)

// TestPredefinedTables はRFC 8878 Appendix Aの既知状態と全遷移の範囲を確認する。
func TestPredefinedTables(t *testing.T) {
	for column, symbols := range []int{36, 21, 53} {
		table, used, err := sequenceTable(nil, 0, symbols)
		if err != nil || used != 0 || len(table.cells) != 1<<uint(table.log) {
			t.Fatal(column, used, err)
		}
		for _, cell := range table.cells {
			if cell.width > uint8(table.log) || int(cell.base)+(1<<cell.width) > len(table.cells) {
				t.Fatal("invalid transition", column, cell)
			}
		}
		before := append([]fseCell(nil), table.cells...)
		var scratch [512]fseCell
		if _, _, err = sequenceTableInto([]byte{0}, 1, symbols, scratch[:]); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(table.cells, before) {
			t.Fatal("shared table changed")
		}
	}
	for _, tc := range []struct {
		column, state int
		cell          fseCell
	}{
		{0, 0, fseCell{0, 4, 0}}, {0, 2, fseCell{1, 5, 32}}, {0, 60, fseCell{35, 6, 0}}, {0, 63, fseCell{32, 6, 0}},
		{1, 1, fseCell{6, 4, 0}}, {1, 15, fseCell{7, 4, 16}}, {1, 27, fseCell{28, 5, 0}}, {1, 31, fseCell{24, 5, 0}},
		{2, 0, fseCell{0, 6, 0}}, {2, 23, fseCell{2, 4, 0}}, {2, 57, fseCell{52, 6, 0}}, {2, 63, fseCell{46, 6, 0}},
	} {
		if got := predefinedTables[tc.column].cells[tc.state]; got != tc.cell {
			t.Fatal(tc.column, tc.state, got, tc.cell)
		}
	}
	for _, symbols := range []int{-1, 0, 12, 29, 256} {
		if _, _, err := sequenceTable(nil, 0, symbols); err == nil {
			t.Fatal("unsupported predefined alphabet accepted", symbols)
		}
	}
}

// TestPredefinedOffsetsBeyondWindow は定義済み表でも1MiBを超えるoffsetを拒否する。
func TestPredefinedOffsetsBeyondWindow(t *testing.T) {
	for state, cell := range predefinedTables[1].cells {
		if cell.symbol <= 20 {
			continue
		}
		// literal長0・参照長3、offsetの追加bitは0。初期状態はML・OF・LLの順に書く。
		stream := make([]byte, 8)
		position := int(cell.symbol) + 6
		value := uint64(state)<<uint(position) | uint64(1)<<uint(position+5+6)
		for i := range stream {
			stream[i] = byte(value >> uint(8*i))
		}
		stream = stream[:(position+5+6+1+7)/8]
		payload := append([]byte{0, 1, 0}, stream...)
		header := len(payload)<<3 | 5
		frame := append([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, byte(header), 0, 0}, payload...)
		if partial, err := Decode(frame, 3); err != ErrInvalid || partial != nil {
			t.Fatal("oversized offset accepted", cell.symbol, err)
		}
	}
}
