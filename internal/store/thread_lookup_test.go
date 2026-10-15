// 投稿履歴の複製を省いても再送キー・期限・日時条件と返却値の独立性を保つことを検査する。
package store

import (
	"testing"

	"oimobbs/internal/domain"
)

func TestThreadDedupRecordBoundaries(t *testing.T) {
	id := domain.Hash{1}
	d := &domain.Dedup{Mode: "explicit", KeyID: 1, Subject: domain.Hash{2}, Request: domain.Hash{3}, RequestID: &id, Expires: 100}
	log := &ThreadLog{records: []ThreadRecord{{ID: domain.ID{1}, Dedup: d}}}
	want := *d
	want.Request = domain.Hash{4}
	got, ok := log.DedupRecord(&want, 99)
	if !ok || got.Dedup.Request != d.Request {
		t.Fatal("explicit body conflict was hidden")
	}
	got.Dedup.Subject = domain.Hash{9}
	*got.Dedup.RequestID = domain.Hash{9}
	if d.Subject != (domain.Hash{2}) || *d.RequestID != id {
		t.Fatal("lookup exposed mutable record")
	}
	for _, damage := range []string{"expired", "id", "subject", "key", "mode", "missing"} {
		copy := *d
		now := domain.Time(99)
		switch damage {
		case "expired":
			now = 100
		case "id":
			other := domain.Hash{4}
			copy.RequestID = &other
		case "subject":
			copy.Subject = domain.Hash{4}
		case "key":
			copy.KeyID++
		case "mode":
			copy.Mode = "implicit"
		case "missing":
			copy.RequestID = nil
		}
		if _, ok := log.DedupRecord(&copy, now); ok {
			t.Fatal("different or expired key matched", damage)
		}
	}
	d.Mode, d.RequestID = "implicit", nil
	want = *d
	if _, ok := log.DedupRecord(&want, 99); !ok {
		t.Fatal("implicit match missing")
	}
	want.Request = domain.Hash{4}
	if _, ok := log.DedupRecord(&want, 99); ok {
		t.Fatal("implicit different request matched")
	}
}

func TestThreadPublicationDates(t *testing.T) {
	log := &ThreadLog{records: []ThreadRecord{{Type: "create", Committed: 1e9}}}
	check := func(modified domain.Time, safe, exact bool) {
		t.Helper()
		m, s, e := log.PublicationDates()
		if m != modified || s != safe || e != exact {
			t.Fatal(m, s, e)
		}
	}
	check(1e9, true, true)
	log.records = append(log.records, ThreadRecord{Type: "append", Committed: 1e9 + 1})
	check(1e9+1, true, false)
	log.records = append(log.records, ThreadRecord{Type: "append", Committed: 2e9})
	check(2e9, true, true)
	log.records = append(log.records, ThreadRecord{Type: "append", Committed: 1e9})
	check(1e9, false, false)
	log.records = append(log.records, ThreadRecord{Type: "redact", Committed: 3e9})
	check(3e9, false, true)
}
