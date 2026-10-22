// 再送索引が線形参照と同じ期限・主体・明示ID競合・履歴順を保ち、packで私的keyを消すことを検査する。
package store

import (
	"oimobbs/internal/domain"
	"reflect"
	"testing"
)

func referenceDedupRecord(records []ThreadRecord, want *domain.Dedup, now domain.Time) (ThreadRecord, bool) {
	if want == nil {
		return ThreadRecord{}, false
	}
	for _, record := range records {
		d := record.Dedup
		if d == nil || now >= d.Expires || d.Mode != want.Mode || d.KeyID != want.KeyID || d.Subject != want.Subject {
			continue
		}
		if d.Mode == "explicit" {
			if d.RequestID == nil || want.RequestID == nil || *d.RequestID != *want.RequestID {
				continue
			}
		} else if d.Request != want.Request {
			continue
		}
		return cloneThreadRecord(record), true
	}
	return ThreadRecord{}, false
}

func TestThreadDedupIndexMatchesReferenceAcrossAppendClockAndPack(t *testing.T) {
	var records []ThreadRecord
	for i := 0; i < 512; i++ {
		requestID := domain.Hash{byte(i % 17)}
		mode := "implicit"
		if i%2 == 0 {
			mode = "explicit"
		}
		d := &domain.Dedup{Mode: mode, KeyID: uint32(i % 3), Subject: domain.Hash{byte(i % 9)}, RequestID: &requestID, Request: domain.Hash{byte(i % 251)}, Expires: domain.Time(100 + i/4)}
		records = append(records, ThreadRecord{ID: domain.ID{byte(i), byte(i >> 8)}, Dedup: d})
	}
	log := &ThreadLog{records: records[:128]}
	check := func() {
		t.Helper()
		for _, now := range []domain.Time{0, 99, 140, 300, 100} {
			for i, record := range records {
				want := *record.Dedup
				switch i % 5 {
				case 0:
					want.Request[0] ^= 7
				case 1:
					want.KeyID++
				case 2:
					want.Subject[0] ^= 13
				case 3:
					want.RequestID = nil
				}
				got, found := log.DedupRecord(&want, now)
				expected, exists := referenceDedupRecord(log.records, &want, now)
				if found != exists || !reflect.DeepEqual(got, expected) {
					t.Fatal("線形照合と不一致", i, now, found, exists)
				}
			}
		}
	}
	check()
	log.records = append(log.records, records[128:]...)
	check()
	log.replaceRecords(retainPackRecords(log.records, 140))
	if log.dedupIndex != nil || log.dedupIndexed != 0 {
		t.Fatal("pack後も古いHMAC索引を保持した")
	}
	check()
	for _, indices := range log.dedupIndex {
		for _, index := range indices {
			if log.records[index].Dedup == nil {
				t.Fatal("回収済みの再送keyを索引へ戻した")
			}
		}
	}
}
