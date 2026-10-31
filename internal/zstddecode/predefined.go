// 定義済みFSE表を公開形式から構成し、共有する読み取り専用表として保持する。
package zstddecode

import (
	"math/bits"
	"oimobbs/internal/zstdformat"
)

var predefinedTables = buildPredefinedTables()

// buildPredefinedTables は低頻度記号を末尾へ置き、残る状態を規定のstepで配る。
func buildPredefinedTables() [3]fseTable {
	var tables [3]fseTable
	for column := range tables {
		norm, log, length := zstdformat.Predefined(column)
		size := 1 << log
		cells := make([]fseCell, size)
		high := size - 1
		for symbol, n := range norm[:length] {
			if n < 0 {
				cells[high].symbol = uint8(symbol)
				high--
			}
		}
		position, step := 0, size/2+size/8+3
		for symbol, n := range norm[:length] {
			for range n {
				cells[position].symbol = uint8(symbol)
				position = (position + step) & (size - 1)
				for position > high {
					position = (position + step) & (size - 1)
				}
			}
			if n < 0 {
				norm[symbol] = 1
			}
		}
		for i := range cells {
			symbol := cells[i].symbol
			n := norm[symbol]
			norm[symbol]++
			width := int(log) - (bits.Len(uint(n)) - 1)
			cells[i].width = uint8(width)
			cells[i].base = uint16((n << uint(width)) - size)
		}
		tables[column] = fseTable{cells: cells, log: int(log)}
	}
	return tables
}

// predefinedTable は参照列の記号数を対応する定義済み表へ写す。
func predefinedTable(symbols int) (fseTable, int, error) {
	switch symbols {
	case 36:
		return predefinedTables[0], 0, nil
	case 21:
		return predefinedTables[1], 0, nil
	case 53:
		return predefinedTables[2], 0, nil
	default:
		return fseTable{}, 0, ErrInvalid
	}
}
