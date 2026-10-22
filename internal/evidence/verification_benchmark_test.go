// 署名済み長文の公開検証とjournal行検証のCPU・一時割り当てを測る。
package evidence

import (
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkEvidenceVerification(b *testing.B) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	source := Source{domain.ID{1}, 20261017, 1}
	payload, err := json.Marshal(testPayload{source.Owner, domain.U64(source.Subkey), domain.U64(source.Seq), strings.Repeat("検証用の本文", 400)})
	if err != nil {
		b.Fatal(err)
	}
	event, err := Seal(source, domain.ID{2}, "attempt", payload, domain.Hash{}, 10, key)
	if err != nil {
		b.Fatal(err)
	}
	value, err := json.Marshal(event)
	if err != nil {
		b.Fatal(err)
	}
	public := key.Public().(ed25519.PublicKey)
	j := &Journal{owner: source.Owner, day: source.Subkey, keyID: 10, key: key, validate: testValidator}
	b.Run("verify", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := Verify(source, event, domain.Hash{}, 10, public); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("journal_value", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := j.validateValue("attempt", event.RecordID.String(), nil, value); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkJournalRecovery は同じ257記録の読取り専用検査と更新可能な復旧を実ファイルで測る。
func BenchmarkJournalRecovery(b *testing.B) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	owner := domain.ID{1}
	parent := b.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(parent, "20261017")
	j, err := OpenJournal(path, owner, 20261017, 10, key, testValidator)
	if err != nil {
		b.Fatal(err)
	}
	build := func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), strings.Repeat("検証用の本文", 400)})
	}
	if _, saved := j.Append(domain.NewID(), "attempt", 1, build); saved.Status != store.Durable {
		b.Fatal(saved)
	}
	for batch := 0; batch < 4; batch++ {
		requests := make([]AppendRequest, 64)
		for i := range requests {
			requests[i] = AppendRequest{ID: domain.NewID(), Kind: "attempt", Committed: 1, Build: build}
		}
		if _, saved := j.AppendBatch(requests); saved.Status != store.Durable {
			b.Fatal(saved)
		}
	}
	if err := j.Close(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := InspectJournal(path, owner, 20261017, 10, key, testValidator); err != nil {
			b.Fatal(err)
		}
		opened, err := OpenJournal(path, owner, 20261017, 10, key, testValidator)
		if err != nil {
			b.Fatal(err)
		}
		if err := opened.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
