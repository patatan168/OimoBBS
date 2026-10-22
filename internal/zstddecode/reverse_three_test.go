// 連続した3フィールドのbit読取りを、個別読取りと境界・エラーまで照合する。
package zstddecode

import (
	"math/rand"
	"testing"
)

func TestReverseThreeReference(t *testing.T) {
	rng := rand.New(rand.NewSource(85))
	for size := 0; size <= 80; size++ {
		data := make([]byte, size)
		rng.Read(data)
		for position := -1; position <= size*8+1; position += 3 {
			widths := [][3]int{{0, 0, 0}, {20, 16, 16}, {9, 9, 9}, {32, 0, 0}, {32, 32, 32}, {-1, 1, 0}, {0, 33, 0}}
			for range 10 {
				widths = append(widths, [3]int{rng.Intn(35) - 1, rng.Intn(35) - 1, rng.Intn(35) - 1})
			}
			for _, w := range widths {
				want := bitStream{data: data, position: position}
				x, y, z := want.reverse(w[0]), want.reverse(w[1]), want.reverse(w[2])
				got := bitStream{data: data, position: position}
				a, b, c := got.reverseThree(w[0], w[1], w[2])
				if a != x || b != y || c != z || got.position != want.position || got.invalid != want.invalid {
					t.Fatalf("size=%d position=%d widths=%v: got=%x/%x/%x/%d/%v want=%x/%x/%x/%d/%v", size, position, w, a, b, c, got.position, got.invalid, x, y, z, want.position, want.invalid)
				}
			}
		}
	}
}
