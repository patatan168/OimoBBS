// 重複除外による最小frameと候補順・所有権の維持を、個別に圧縮した全候補と比較する。
package zstdencode

import (
	"bytes"
	"oimobbs/internal/testutil"
	"reflect"
	"testing"
)

func TestArchiveEquivalentCandidates(t *testing.T) {
	text, entropy := testutil.DATFixture("text"), testutil.DATFixture("entropy")
	mixed := append(bytes.Clone(text[:blockLimit]), entropy[:blockLimit]...)
	for _, raw := range [][]byte{nil, []byte("short"), text, entropy, mixed} {
		for _, log := range []uint{7, 9} {
			for _, optimize := range []bool{false, true} {
				options := []ArchiveOptions{{AccuracyLog: log, OptimizeEntropy: optimize}, {HashBytes: 5, AccuracyLog: log, OptimizeEntropy: optimize}, {HashBytes: 7, AccuracyLog: log, OptimizeEntropy: optimize}, {HashBytes: 4, AccuracyLog: log, OptimizeEntropy: optimize}}
				original := append([]ArchiveOptions(nil), options...)
				var want []byte
				for _, option := range options {
					candidate, err := (&Encoder{}).EncodeArchive(raw, option)
					if err != nil {
						t.Fatal(err)
					}
					if want == nil || len(candidate) < len(want) {
						want = candidate
					}
				}
				got, err := (&Encoder{}).EncodeBestArchive(raw, options)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("candidate minimum changed", len(raw), log, optimize, err)
				}
				if !reflect.DeepEqual(options, original) {
					t.Fatal("caller options changed")
				}
			}
		}
	}
}

func TestArchiveOptionPruningConditions(t *testing.T) {
	text, entropy := testutil.DATFixture("text"), testutil.DATFixture("entropy")
	mixed := append(bytes.Clone(text[:blockLimit]), entropy[:blockLimit]...)
	options := []ArchiveOptions{{AccuracyLog: 9, OptimizeEntropy: true}, {HashBytes: 7, AccuracyLog: 9, OptimizeEntropy: true}, {HashBytes: 4, AccuracyLog: 9, OptimizeEntropy: true}}
	for _, tc := range []struct {
		raw   []byte
		count int
	}{{text, 3}, {entropy, 2}, {mixed, 3}} {
		if got := uniqueArchiveOptions(tc.raw, options); len(got) != tc.count {
			t.Fatal("wrong duplicate decision", len(tc.raw), len(got), tc.count)
		}
	}
	differentLog := []ArchiveOptions{{AccuracyLog: 8}, {HashBytes: 7, AccuracyLog: 9}}
	if got := uniqueArchiveOptions(entropy, differentLog); len(got) != 2 {
		t.Fatal("different entropy precision was pruned")
	}
	differentEntropy := []ArchiveOptions{{AccuracyLog: 9}, {HashBytes: 7, AccuracyLog: 9, OptimizeEntropy: true}}
	if got := uniqueArchiveOptions(entropy, differentEntropy); len(got) != 2 {
		t.Fatal("different entropy selection was pruned")
	}
}

// TestUniformArchiveValidation は高速経路でも全候補の検査と返却配列の所有権を維持する。
func TestUniformArchiveValidation(t *testing.T) {
	raw := bytes.Repeat([]byte{0xee}, blockLimit+16)
	var e Encoder
	for _, options := range [][]ArchiveOptions{nil, {{AccuracyLog: 9}, {HashBytes: 3, AccuracyLog: 9}}, {{AccuracyLog: 6}}} {
		if frame, err := e.EncodeBestArchive(raw, options); err == nil || frame != nil {
			t.Fatal("invalid uniform archive accepted")
		}
	}
	frame, err := e.EncodeArchive(raw, ArchiveOptions{AccuracyLog: 9})
	if err != nil {
		t.Fatal(err)
	}
	expected := bytes.Clone(frame)
	raw[0] = 0
	e.Encode(raw)
	e.Encode(bytes.Repeat([]byte{1}, blockLimit+15))
	if !bytes.Equal(frame, expected) {
		t.Fatal("uniform frame changed after reuse")
	}
}
