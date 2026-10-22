// 単一symbolの列でも状態・symbol・modeの検査を維持する。
package zstddecode

import (
	"reflect"
	"testing"
)

// FuzzFSETransitionBounds は表構成時に全遷移が表内へ収まる性質を検査する。
// シーケンスの初期状態もlog bitなので、復号中の表参照は常にこの範囲内になる。
func FuzzFSETransitionBounds(f *testing.F) {
	for _, data := range [][]byte{{0x10, 0x3f}, {0xff}, {0, 0, 0, 0}, {0x21, 0x32, 0x54, 0x76, 0x98}} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var scratch [512]fseCell
		for i := range scratch {
			scratch[i] = fseCell{255, 255, 65535}
		}
		for _, symbols := range []int{12, 21, 36, 53, 256} {
			table, used, err := readTable(data, symbols, 9)
			reused, reusedUsed, reusedErr := readTableInto(data, symbols, 9, scratch[:])
			if (err == nil) != (reusedErr == nil) || used != reusedUsed || err == nil && !reflect.DeepEqual(table, reused) {
				t.Fatal("scratch changed table or validation", symbols, err, reusedErr)
			}
			if err != nil {
				continue
			}
			if len(table.cells) != 1<<uint(table.log) {
				t.Fatal("initial state range exceeds table")
			}
			for _, cell := range table.cells {
				last := int(cell.base) + (1 << uint(cell.width)) - 1
				if int(cell.symbol) >= symbols || last >= len(table.cells) {
					t.Fatal("transition exceeds table", cell, table.log)
				}
			}
		}
	})
}

func TestSequenceRLEStateAndSymbol(t *testing.T) {
	table, used, err := sequenceTable([]byte{52}, 1, 53)
	if err != nil || used != 1 {
		t.Fatal(used, err)
	}
	cell, err := table.cell(0)
	if err != nil || cell.symbol != 52 || cell.width != 0 || cell.base != 0 {
		t.Fatal(cell, err)
	}
	for _, state := range []int{-1, 1, 1000} {
		if _, err := table.cell(state); err == nil {
			t.Fatal("invalid state accepted", state)
		}
	}
	if _, err := (fseTable{}).cell(0); err == nil {
		t.Fatal("empty table accepted")
	}
	for _, mode := range []int{0, 1, 3} {
		if _, _, err := sequenceTable(nil, mode, 53); err == nil {
			t.Fatal("missing table accepted", mode)
		}
	}
	if _, _, err := sequenceTable([]byte{53}, 1, 53); err == nil {
		t.Fatal("out-of-range symbol accepted")
	}
}
