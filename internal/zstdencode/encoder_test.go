// 送信frameを既存の独立decoderで検査し、境界・再利用・多様なliteralを確認する。
package zstdencode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"oimobbs/internal/testutil"
	"strings"
	"testing"
)

func TestIndependentFrames(t *testing.T) {
	encoder := &Encoder{}
	bodies := [][]byte{nil, []byte("a"), bytes.Repeat([]byte{1}, 300000), []byte(strings.Repeat("名前<>sage<>日本語の文章と返信 0123456789\n", 9000))}
	random := rand.New(rand.NewPCG(9, 23))
	for _, size := range []int{31, 255, 256, 1023, 4095, 65791, 65792, 131071, 131072, 131073, 1048576, 1048583} {
		b := make([]byte, size)
		for i := range b {
			b[i] = byte(random.Uint32())
		}
		bodies = append(bodies, b)
		b = make([]byte, size)
		for i := range b {
			b[i] = []byte("0123456789abcdef")[random.IntN(16)]
		}
		bodies = append(bodies, b)
	}
	for i, b := range bodies {
		t.Run(fmt.Sprint(i, "-", len(b)), func(t *testing.T) {
			encoded := encoder.Encode(b)
			decoded, err := testutil.DecodeZstd(encoded)
			if err != nil || !bytes.Equal(decoded, b) {
				t.Fatalf("size=%d encoded=%d decode=%v decoded=%d", len(b), len(encoded), err, len(decoded))
			}
			if !bytes.Equal(encoded, encoder.Encode(b)) {
				t.Fatal("nondeterministic")
			}
		})
	}
}

// FuzzIndependentFrames は任意byte・繰り返し・偏ったalphabetを独立decoderで検証する。
func FuzzIndependentFrames(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("aaaaaa"), []byte("日本語と0123456789abcdef"), bytes.Repeat([]byte{0, 1, 2, 128, 255}, 123)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			t.Skip()
		}
		e := &Encoder{}
		for _, raw := range [][]byte{body, bytes.Repeat(body, min(20, (2<<20)/(len(body)+1)))} {
			encoded := e.Encode(raw)
			decoded, err := testutil.DecodeZstd(encoded)
			if err != nil || !bytes.Equal(raw, decoded) {
				t.Fatalf("roundtrip size=%d: %v", len(raw), err)
			}
		}
	})
}

// TestStructuredCorpora は日本語以外の全byteと偏った頻度を再利用するworkerで検査する。
func TestStructuredCorpora(t *testing.T) {
	e := &Encoder{}
	random := rand.New(rand.NewPCG(17, 39))
	for alphabet := 2; alphabet <= 256; alphabet++ {
		raw := make([]byte, 4096+alphabet*37)
		for i := range raw {
			v := random.IntN(alphabet)
			if i%3 == 0 {
				v = 0
			}
			raw[i] = byte(v)
		}
		if alphabet%7 == 0 {
			raw = bytes.Repeat(raw, 12)
		}
		encoded := e.Encode(raw)
		decoded, err := testutil.DecodeZstd(encoded)
		if err != nil || !bytes.Equal(raw, decoded) {
			t.Fatalf("alphabet=%d: %v", alphabet, err)
		}
	}
}

// TestMixedBlockModes は文字種の切替とwindowを跨ぐ参照を独立decoderで検査する。
func TestMixedBlockModes(t *testing.T) {
	random := rand.New(rand.NewPCG(31, 71))
	noise := make([]byte, blockLimit)
	for i := range noise {
		noise[i] = []byte("0123456789abcdef")[random.IntN(16)]
	}
	text := []byte(strings.Repeat("日本語とEnglish、日時や記号 <> >> の混在です。", 4000))
	raw := append(bytes.Clone(noise), text...)
	raw = append(raw, noise...)
	raw = bytes.Repeat(raw, 3)
	e := &Encoder{}
	encoded := e.Encode(raw)
	decoded, err := testutil.DecodeZstd(encoded)
	if err != nil || !bytes.Equal(raw, decoded) {
		t.Fatal("block modes roundtrip", err)
	}
	next := e.Encode(testutil.DATFixture("mixed"))
	fresh := (&Encoder{}).Encode(testutil.DATFixture("mixed"))
	if !bytes.Equal(next, fresh) {
		t.Fatal("previous frame affected encoding")
	}
}

// TestBitPrices は固定小数点の尺度・単調性・power-of-twoの境界を確認する。
func TestBitPrices(t *testing.T) {
	for exponent := 0; exponent <= 17; exponent++ {
		if got := bitPrice(1<<exponent, 1); got != exponent*256 {
			t.Fatalf("power %d price %d", exponent, got)
		}
	}
	previous := 1 << 30
	for count := 1; count <= blockLimit; count++ {
		price := bitPrice(blockLimit, count)
		if price < 0 || price > previous {
			t.Fatalf("nonmonotone at %d: %d", count, price)
		}
		previous = price
	}
}

// TestReturnedFrameOwnership は返却済みframeがworker再利用や入力変更で壊れないことを検査する。
func TestReturnedFrameOwnership(t *testing.T) {
	e := &Encoder{}
	raw := testutil.DATFixture("mixed")
	want := bytes.Clone(raw)
	frame := e.Encode(raw)
	for i := range raw {
		raw[i] ^= 0xff
	}
	for _, next := range [][]byte{nil, []byte("a"), testutil.DATFixture("entropy"), testutil.DATFixture("text")} {
		e.Encode(next)
		decoded, err := testutil.DecodeZstd(frame)
		if err != nil || !bytes.Equal(decoded, want) {
			t.Fatal("returned frame changed after reuse", err)
		}
	}
}

// TestUnvisitedRepeatCandidate は短いrepeatで探索を止めても、未確認の長い候補を捨てない。
func TestUnvisitedRepeatCandidate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		phrase []byte
		mask   uint64
	}{
		{"wide-alphabet", []byte("abcDEFGHIJKLMNOPQRSTUVWXYZabcdef"), 0xffffffffff},
		{"narrow-alphabet", []byte("abc" + strings.Repeat("d", 29)), 0xffffffffffffff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := make([]byte, 160)
			copy(body[64:], tc.phrase)
			copy(body[112:], "abcX")
			copy(body[128:], tc.phrase)
			e := &Encoder{}
			hash := longHash(binary.LittleEndian.Uint64(body[64:]), tc.mask)
			e.long[(hash>>16)&((1<<15)-1)] = uint64(hash)<<32 | 65
			e.parse(body, 128, 160, [3]int{8, 16, 64})
			if len(e.coded) != 1 || len(e.literals) != 0 || e.nextRepeats[0] != 64 {
				t.Fatalf("unvisited long repeat lost: sequences=%d literals=%d repeats=%v", len(e.coded), len(e.literals), e.nextRepeats)
			}
		})
	}
}
