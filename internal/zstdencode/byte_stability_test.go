// worker再利用時のHTTP/保存1・6のbyteと、旧保存9候補のサイズ非増加・独立復号を検査する。
package zstdencode

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"oimobbs/internal/testutil"
	"os"
	"testing"
)

type stableInput struct {
	name string
	raw  []byte
}

// stableInputs はblock・短い探索表の境界と、実保存のDAT・一様blockを含む固定入力を返す。
func stableInputs() []stableInput {
	inputs := []stableInput{{"text", testutil.DATFixture("text")}, {"mixed", testutil.DATFixture("mixed")}, {"entropy", testutil.DATFixture("entropy")}, {"rle", bytes.Repeat([]byte{0xee}, 500000)}}
	for _, size := range []int{17, 131072, 131073, 131080, 131087, 131088, 131089} {
		for _, value := range []byte{0, 255} {
			inputs = append(inputs, stableInput{fmt.Sprintf("uniform-%d-%d", size, value), bytes.Repeat([]byte{value}, size)})
		}
	}
	rng := rand.New(rand.NewPCG(3781, 619))
	for _, size := range []int{0, 31, 511, 512, 32768, 32769, 131071, 131072, 131073} {
		raw := make([]byte, size)
		for i := range raw {
			raw[i] = "abcde0123456789<>日本語"[rng.IntN(len("abcde0123456789<>日本語"))]
		}
		inputs = append(inputs, stableInput{fmt.Sprint(size), raw})
	}
	return inputs
}

// stableOptions は過去の保存level 1/6/9の候補を回帰試験用に再現する。nilはHTTP用。
func stableOptions(codec string, size int) []ArchiveOptions {
	switch codec {
	case "archive1":
		return []ArchiveOptions{{AccuracyLog: 7}}
	case "archive6":
		return []ArchiveOptions{{AccuracyLog: 8}}
	case "archive9":
		if size >= 16<<10 {
			return []ArchiveOptions{{AccuracyLog: 9, OptimizeEntropy: true}, {HashBytes: 7, AccuracyLog: 9, OptimizeEntropy: true}, {HashBytes: 4, AccuracyLog: 9, OptimizeEntropy: true}}
		}
		return []ArchiveOptions{{AccuracyLog: 8}, {AccuracyLog: 9}, {HashBytes: 7, AccuracyLog: 8}, {HashBytes: 4, AccuracyLog: 9}}
	}
	return nil
}

// TestEncodingByteStability は最適化前162b733のHTTP/保存1・6のbyteと、旧保存9候補のサイズ非増加・独立復号を照合する。
func TestEncodingByteStability(t *testing.T) {
	raw, err := os.ReadFile("testdata/encoding-stability-162b733.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Bytes int    `json:"bytes"`
		SHA   string `json:"sha256"`
	}
	if err = json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	var e Encoder
	checks := 0
	for _, input := range stableInputs() {
		for _, codec := range []string{"http", "archive1", "archive6", "archive9"} {
			var frame []byte
			if options := stableOptions(codec, len(input.raw)); options == nil {
				frame = e.Encode(input.raw)
			} else {
				frame, err = e.EncodeBestArchive(input.raw, options)
				if err != nil {
					t.Fatal(err)
				}
			}
			hash := sha256.Sum256(frame)
			key := input.name + "/" + codec
			want, ok := expected[key]
			if !ok {
				t.Fatal("missing frame", key)
			}
			if codec == "archive9" {
				if len(frame) > want.Bytes {
					t.Fatalf("archive size increased: %s bytes=%d previous=%d", key, len(frame), want.Bytes)
				}
				decoded, err := testutil.DecodeZstd(frame)
				if err != nil || !bytes.Equal(decoded, input.raw) {
					t.Fatal("independent decode", key, err)
				}
			} else if len(frame) != want.Bytes || hex.EncodeToString(hash[:]) != want.SHA {
				t.Fatalf("frame changed: %s bytes=%d sha256=%x", key, len(frame), hash)
			}
			checks++
		}
	}
	if checks != len(expected) {
		t.Fatal("unexercised stability fixtures")
	}
}
