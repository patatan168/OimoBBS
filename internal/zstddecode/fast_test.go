// bit抽出と重複履歴copyを単純な参照処理と照合する。
package zstddecode

import (
	"bytes"
	"math/rand"
	"testing"

	"oimobbs/internal/zstdencode"
)

func TestBitExtractReference(t *testing.T) {
	rng := rand.New(rand.NewSource(53))
	for size := 0; size <= 32; size++ {
		data := make([]byte, size)
		rng.Read(data)
		for position := -1; position <= size*8+1; position++ {
			for width := -1; width <= 33; width++ {
				b := bitStream{data: data}
				got := b.extract(position, width)
				invalid := width < 0 || width > 32 || position < 0 || position+width > size*8
				var want uint32
				if !invalid {
					for i := 0; i < width; i++ {
						want |= uint32(data[(position+i)/8]>>uint((position+i)%8)&1) << uint(i)
					}
				}
				if got != want || b.invalid != invalid {
					t.Fatalf("size=%d position=%d width=%d: got %x/%v want %x/%v", size, position, width, got, b.invalid, want, invalid)
				}
			}
		}
	}
}

func TestDecodeBoundedOwnershipAndLimits(t *testing.T) {
	for _, size := range []int{0, 1, 128<<10 - 1, 128 << 10, 128<<10 + 1, 2 << 20, (8 << 20) + 20} {
		raw := bytes.Repeat([]byte("abcde"), (size+4)/5)[:size]
		var encoder zstdencode.Encoder
		frame := encoder.Encode(raw)
		out, err := DecodeBounded(frame, size, size)
		if err != nil || !bytes.Equal(out, raw) {
			t.Fatalf("size=%d: %v", size, err)
		}
		if size > 0 {
			if bad, err := DecodeBounded(frame, size, size-1); err == nil || bad != nil {
				t.Fatalf("limit exceeded: size=%d", size)
			}
		}
		for _, invalidLimit := range []int{-1, (8 << 20) + 21} {
			if bad, err := DecodeBounded(frame, size, invalidLimit); err == nil || bad != nil {
				t.Fatal("invalid limit accepted")
			}
		}
		clear(frame)
		if !bytes.Equal(out, raw) {
			t.Fatal("result aliases compressed input")
		}
	}
}

func TestCopyMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(54))
	for size := 1; size <= 256; size++ {
		prefix := make([]byte, size)
		rng.Read(prefix)
		for offset := 1; offset <= size; offset++ {
			for _, n := range []int{0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 127, 256, 513} {
				want := bytes.Clone(prefix)
				for range n {
					want = append(want, want[len(want)-offset])
				}
				out := make([]byte, size, size+n)
				copy(out, prefix)
				got := copyMatch(out, offset, n)
				if !bytes.Equal(got, want) {
					t.Fatalf("size=%d offset=%d n=%d", size, offset, n)
				}
			}
		}
	}
}
