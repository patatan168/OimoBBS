// 署名対象の長さ付き列を独立した既存実装と固定値で照合し、確保とCPUの削減を検査する。
package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"oimobbs/internal/domain"
	"strconv"
	"strings"
	"testing"
)

func referenceEventDigest(source Source, id domain.ID, kind string, payload, previous domain.Hash) domain.Hash {
	h := sha256.New()
	for _, v := range [][]byte{[]byte("oimo/evidence/v1"), source.Owner[:], []byte(strconv.FormatUint(source.Subkey, 10)), []byte(strconv.FormatUint(source.Seq, 10)), id[:], []byte(kind), payload[:], previous[:]} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		h.Write(n[:])
		h.Write(v)
	}
	var result domain.Hash
	copy(result[:], h.Sum(nil))
	return result
}

func TestEventDigestEquivalent(t *testing.T) {
	if got := digest(Source{domain.ID{3}, 20261024, 42}, domain.ID{4}, "evidence_proposal", domain.Hash{1}, domain.Hash{2}).String(); got != "2040af9c2ae84d3adde6e86aa2efe2f184f45da8142e3a9681de090a1b504d59" {
		t.Fatal("fixed vector", got)
	}

	for _, n := range []uint64{0, 1, 9, 10, 20261024, ^uint64(0)} {
		for _, kind := range []string{"attempt", "evidence_proposal", "thread_admin_decision", "", strings.Repeat("x", 512)} {
			src := Source{domain.ID{3}, n, n}
			got, want := digest(src, domain.ID{4}, kind, domain.Hash{1}, domain.Hash{2}), referenceEventDigest(src, domain.ID{4}, kind, domain.Hash{1}, domain.Hash{2})
			if got != want {
				t.Fatal(n, kind, got, want)
			}
		}
	}
}

func FuzzEventDigestEquivalent(f *testing.F) {
	f.Add(uint64(20261024), uint64(42), "evidence_proposal", []byte{1})
	f.Fuzz(func(t *testing.T, day, seq uint64, kind string, body []byte) {
		src := Source{domain.ID{3}, day, seq}
		p := sha256.Sum256(body)
		if digest(src, domain.ID{4}, kind, p, domain.Hash{2}) != referenceEventDigest(src, domain.ID{4}, kind, p, domain.Hash{2}) {
			t.Fatal("digest differs")
		}
	})
}

func BenchmarkEventDigest(b *testing.B) {
	src := Source{domain.ID{3}, 20261024, 42}
	for _, fast := range []bool{false, true} {
		b.Run(fmt.Sprint(fast), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if fast {
					_ = digest(src, domain.ID{4}, "evidence_proposal", domain.Hash{1}, domain.Hash{2})
				} else {
					_ = referenceEventDigest(src, domain.ID{4}, "evidence_proposal", domain.Hash{1}, domain.Hash{2})
				}
			}
		})
	}
}
