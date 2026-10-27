// 認証アプリ登録用の短いURIを、標準ライブラリーだけでQR Model 2のPNGへ符号化する。
package adminauth

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
)

type qrSpec struct{ version, data, blocks, ecc int }

// 誤り訂正M。入力長とCPU・画像寸法の上限を固定する。
var qrSpecs = [...]qrSpec{{10, 216, 5, 26}, {15, 415, 10, 24}, {20, 669, 16, 26}, {25, 1000, 21, 28}}

// EnrollmentQR は最大997バイトを4モジュールの余白付きPNGにする。外部への通信は行わない。
func EnrollmentQR(text string) ([]byte, error) {
	if len(text) == 0 || len(text) > 997 {
		return nil, errors.New("QR input length out of range")
	}
	var spec qrSpec
	for _, candidate := range qrSpecs {
		if len(text)*8+20 <= candidate.data*8 {
			spec = candidate
			break
		}
	}
	q := newQRMatrix(spec.version)
	q.place(qrInterleave(qrPayload(text, spec.data), spec))
	best, score := []bool(nil), int(^uint(0)>>1)
	for mask := 0; mask < 8; mask++ {
		q.mask(mask)
		q.format(mask)
		if value := q.penalty(); value < score {
			score = value
			best = append(best[:0], q.cells...)
		}
		q.mask(mask)
	}
	q.cells = best
	const scale = 4
	side := (q.size + 8) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if !q.cells[y*q.size+x] {
				continue
			}
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.SetGray((x+4)*scale+dx, (y+4)*scale+dy, color.Gray{})
				}
			}
		}
	}
	var out bytes.Buffer
	err := png.Encode(&out, img)
	return out.Bytes(), err
}

func qrPayload(text string, count int) []byte {
	bits := make([]bool, 0, count*8)
	appendBits := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, v&(1<<i) != 0)
		}
	}
	appendBits(4, 4)
	appendBits(len(text), 16)
	for _, b := range []byte(text) {
		appendBits(int(b), 8)
	}
	appendBits(0, min(4, count*8-len(bits)))
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	out := make([]byte, len(bits)/8, count)
	for i, b := range bits {
		if b {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	for pad := byte(0xec); len(out) < count; pad ^= 0xfd {
		out = append(out, pad)
	}
	return out
}

// qrMultiply はGF(256)、原始多項式x^8+x^4+x^3+x^2+1で乗算する。
func qrMultiply(a, b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			result ^= a
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return result
}
func qrRemainder(data []byte, degree int) []byte {
	generator := []byte{1}
	root := byte(1)
	for i := 0; i < degree; i++ {
		next := make([]byte, len(generator)+1)
		for j, c := range generator {
			next[j] ^= c
			next[j+1] ^= qrMultiply(c, root)
		}
		generator = next
		root = qrMultiply(root, 2)
	}
	remainder := make([]byte, degree)
	for _, b := range data {
		factor := b ^ remainder[0]
		copy(remainder, remainder[1:])
		remainder[degree-1] = 0
		for i := range remainder {
			remainder[i] ^= qrMultiply(generator[i+1], factor)
		}
	}
	return remainder
}
func qrInterleave(data []byte, s qrSpec) []byte {
	total := s.data + s.blocks*s.ecc
	shortTotal := total / s.blocks
	shortBlocks := s.blocks - total%s.blocks
	shortData := shortTotal - s.ecc
	blocks := make([][]byte, s.blocks)
	checks := make([][]byte, s.blocks)
	offset := 0
	for i := range blocks {
		n := shortData
		if i >= shortBlocks {
			n++
		}
		blocks[i] = data[offset : offset+n]
		checks[i] = qrRemainder(blocks[i], s.ecc)
		offset += n
	}
	out := make([]byte, 0, total)
	for column := 0; column <= shortData; column++ {
		for _, block := range blocks {
			if column < len(block) {
				out = append(out, block[column])
			}
		}
	}
	for column := 0; column < s.ecc; column++ {
		for _, check := range checks {
			out = append(out, check[column])
		}
	}
	return out
}

type qrMatrix struct {
	size            int
	cells, function []bool
}

func (q *qrMatrix) set(x, y int, dark bool) {
	q.cells[y*q.size+x] = dark
	q.function[y*q.size+x] = true
}
func newQRMatrix(version int) *qrMatrix {
	size := version*4 + 17
	q := &qrMatrix{size: size, cells: make([]bool, size*size), function: make([]bool, size*size)}
	for i := 0; i < size; i++ {
		q.set(6, i, i%2 == 0)
		q.set(i, 6, i%2 == 0)
	}
	for _, center := range [][2]int{{3, 3}, {size - 4, 3}, {3, size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := center[0]+dx, center[1]+dy
				if x < 0 || y < 0 || x >= size || y >= size {
					continue
				}
				d := max(absQR(dx), absQR(dy))
				q.set(x, y, d != 2 && d != 4)
			}
		}
	}
	count := version/7 + 2
	step := ((version*4 + count*2 + 1) / (count*2 - 2)) * 2
	positions := make([]int, count)
	positions[0] = 6
	for i, p := count-1, size-7; i >= 1; i, p = i-1, p-step {
		positions[i] = p
	}
	for i, x := range positions {
		for j, y := range positions {
			if i == 0 && j == 0 || i == 0 && j == count-1 || i == count-1 && j == 0 {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					q.set(x+dx, y+dy, max(absQR(dx), absQR(dy)) != 1)
				}
			}
		}
	}
	q.format(0)
	remainder := version << 12
	for i := 17; i >= 12; i-- {
		if remainder&(1<<i) != 0 {
			remainder ^= 0x1f25 << (i - 12)
		}
	}
	value := version<<12 | remainder
	for i := 0; i < 18; i++ {
		x, y := size-11+i%3, i/3
		dark := value&(1<<i) != 0
		q.set(x, y, dark)
		q.set(y, x, dark)
	}
	return q
}
func absQR(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
func (q *qrMatrix) format(mask int) {
	remainder := mask << 10
	for i := 14; i >= 10; i-- {
		if remainder&(1<<i) != 0 {
			remainder ^= 0x537 << (i - 10)
		}
	}
	value := (mask<<10 | remainder) ^ 0x5412
	bit := func(i int) bool { return value&(1<<i) != 0 }
	for i := 0; i < 6; i++ {
		q.set(8, i, bit(i))
	}
	q.set(8, 7, bit(6))
	q.set(8, 8, bit(7))
	q.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		q.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.set(q.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.set(8, q.size-15+i, bit(i))
	}
	q.set(8, q.size-8, true)
}
func (q *qrMatrix) place(data []byte) {
	index := 0
	for right := q.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for row := 0; row < q.size; row++ {
			y := row
			if (right+1)&2 == 0 {
				y = q.size - 1 - row
			}
			for dx := 0; dx < 2; dx++ {
				pos := y*q.size + right - dx
				if q.function[pos] {
					continue
				}
				if index < len(data)*8 {
					q.cells[pos] = data[index/8]&(1<<uint(7-index%8)) != 0
				}
				index++
			}
		}
	}
}
func qrMasked(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}
func (q *qrMatrix) mask(mask int) {
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			i := y*q.size + x
			if !q.function[i] && qrMasked(mask, x, y) {
				q.cells[i] = !q.cells[i]
			}
		}
	}
}

// penalty は連続色・正方形・位置検出に似た並び・色の偏りを減らすマスクを選ぶ。
func (q *qrMatrix) penalty() int {
	score, dark := 0, 0
	for _, b := range q.cells {
		if b {
			dark++
		}
	}
	for direction := 0; direction < 2; direction++ {
		for line := 0; line < q.size; line++ {
			run, pattern := 0, 0
			previous := false
			for p := 0; p < q.size; p++ {
				x, y := p, line
				if direction == 1 {
					x, y = line, p
				}
				b := q.cells[y*q.size+x]
				if p == 0 || b != previous {
					run = 1
				} else {
					run++
					if run == 5 {
						score += 3
					} else if run > 5 {
						score++
					}
				}
				previous = b
				pattern = (pattern << 1) & 0x7ff
				if b {
					pattern |= 1
				}
				if p >= 10 && (pattern == 0x05d || pattern == 0x5d0) {
					score += 40
				}
				if direction == 0 && x > 0 && y > 0 && b == q.cells[y*q.size+x-1] && b == q.cells[(y-1)*q.size+x] && b == q.cells[(y-1)*q.size+x-1] {
					score += 3
				}
			}
		}
	}
	return score + absQR(dark*20-q.size*q.size*10)/(q.size*q.size)*10
}
