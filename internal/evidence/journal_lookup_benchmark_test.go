// 索引取得部品のメモリ内計測。署名検証/Sync/queue/実環境の速度は測らない。
package evidence

import (
	"bytes"
	"testing"

	"oimobbs/internal/domain"
)

// BenchmarkJournalLookup は同じ固定IDをVisitで探す経路と、現在行索引から探す経路を比較する。
func BenchmarkJournalLookup(b *testing.B) {
	j := &Journal{}
	for i := 0; i < 10000; i++ {
		j.entries = append(j.entries, Entry{Event: Event{RecordID: domain.NewID()}, Payload: []byte("lookup benchmark payload")})
	}
	target := j.entries[len(j.entries)-1].Event.RecordID
	b.Run("visit_10000_rows", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var found Entry
			if e := j.Visit(func(entry Entry) error {
				if entry.Event.RecordID == target {
					found = Entry{Event: entry.Event, Payload: bytes.Clone(entry.Payload)}
				}
				return nil
			}); e != nil || found.Event.RecordID != target {
				b.Fatal("lookup failed", e)
			}
		}
	})
	b.Run("indexed_10000_rows", func(b *testing.B) {
		if _, _, e := j.lookupEntry(target); e != nil {
			b.Fatal(e)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			entry, found, e := j.lookupEntry(target)
			if e != nil || !found || entry.Event.RecordID != target {
				b.Fatal("lookup failed", e)
			}
		}
	})
}
