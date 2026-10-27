// 連続した3つのFSEフィールドを、検査後に一度のword読取りで取り出す。
package zstddecode

import "encoding/binary"

// sequenceThree は表構築時に検証した各0〜20bit・合計52bit以内の幅で読む。
// 通常部分の重複検査を省き、境界では汎用検査へ戻す。
// positionはreverseStreamで初期化し、入力不足はinvalidを立てて呼出元が直後に拒否する。
func (b *bitStream) sequenceThree(first, second, third int) (uint32, uint32, uint32) {
	if first|second|third == 0 {
		return 0, 0, 0
	}
	position := b.position - first - second - third
	if position < 0 || position/8 > len(b.data)-8 {
		return b.reverseThree(first, second, third)
	}
	word := binary.LittleEndian.Uint64(b.data[position/8:]) >> uint(position&7)
	b.position = position
	c := uint32(word & ((uint64(1) << uint(third)) - 1))
	word >>= uint(third)
	middle := uint32(word & ((uint64(1) << uint(second)) - 1))
	word >>= uint(second)
	a := uint32(word & ((uint64(1) << uint(first)) - 1))
	return a, middle, c
}

// reverseThree は個別reverseと同じ順序・終端・invalid状態を保つ。
// 合計56bit以内かつ8byteを安全に読める場合だけまとめ、境界は個別処理する。
func (b *bitStream) reverseThree(first, second, third int) (uint32, uint32, uint32) {
	if first|second|third == 0 {
		return b.reverse(0), 0, 0
	}
	total := first + second + third
	position := b.position - total
	if uint(first) > 32 || uint(second) > 32 || uint(third) > 32 || total > 56 || position < 0 || b.position > len(b.data)*8 || position/8 > len(b.data)-8 {
		return b.reverse(first), b.reverse(second), b.reverse(third)
	}
	word := binary.LittleEndian.Uint64(b.data[position/8:]) >> uint(position&7)
	b.position = position
	c := uint32(word & ((uint64(1) << uint(third)) - 1))
	word >>= uint(third)
	middle := uint32(word & ((uint64(1) << uint(second)) - 1))
	word >>= uint(second)
	a := uint32(word & ((uint64(1) << uint(first)) - 1))
	return a, middle, c
}
