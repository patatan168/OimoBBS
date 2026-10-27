// 非必須ログの署名・符号化・実Syncを含む保存時間を測る。
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"oimobbs/internal/domain"
	"os"
	"testing"
	"time"
)

// BenchmarkOptionalBatchPersistence は隔離一時領域へ256件ずつ保存する。128MiBの実上限を維持する。
func BenchmarkOptionalBatchPersistence(b *testing.B) {
	if b.N > 40 {
		b.Skip("use -benchtime=20x to stay within retention capacity")
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := b.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		b.Fatal(err)
	}
	site := domain.NewID()
	s, err := OpenOptionalStore(root, site, key)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	seed := optionalFixture()
	seed.Site = site
	seed.Received = domain.Time(time.Now().UnixNano())
	seed.Finished = seed.Received + 100
	seed.Until = seed.Received + domain.Time(OptionalRetention)
	if err := s.Write(context.Background(), seed); err != nil {
		b.Fatal(err)
	}
	records := make([]OptionalRecord, MaxOptionalBatch)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range records {
			records[j] = seed
			records[j].ID = domain.NewID()
		}
		for _, err := range s.WriteBatch(context.Background(), records) {
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.StopTimer()
	for _, j := range s.journals {
		if j.seq != uint64(b.N*MaxOptionalBatch+1) {
			b.Fatal("records missing", j.seq)
		}
	}
}
