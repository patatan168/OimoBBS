// 保存I/Oを除くHTTP記録の受け渡し時間と一時確保量を比較する。
package evidence

import (
	"context"
	"testing"
)

func BenchmarkOptionalQueueTransfer(b *testing.B) {
	completed := make(chan struct{}, 1)
	q, err := NewOptionalQueue(func(context.Context, OptionalRecord) error { completed <- struct{}{}; return nil })
	if err != nil {
		b.Fatal(err)
	}
	defer q.Close(context.Background())
	record := optionalFixture()
	record.UserAgent = &HeaderValue{Base64: "dWE=", Display: "ua"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !q.Enqueue(record) {
			b.Fatal("record dropped")
		}
		<-completed
	}
	b.StopTimer()
	if err := q.Close(context.Background()); err != nil {
		b.Fatal(err)
	}
	if q.Status().Saved != uint64(b.N) {
		b.Fatal("records missing")
	}
}
