// 実フォームの構築後に元byteが壊れても、並行照合が必須journalの保存前に拒否する。
package bootstrap

import (
	"bytes"
	"fmt"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"sync/atomic"
	"testing"
	"time"
)

func TestParallelCaptureRejectsBeforeJournalAndRetries(t *testing.T) {
	cfg := testConfig(t)
	report, err := Initialize(cfg, "並行照合")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postcapture.Validate, PostingOptions{ParallelCaptureValidation: true})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	info, err := repo.CreateBoard(t.Context(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	server := formServer(t, repo, report.SiteID, info.ID)
	defer server.Close()
	created, err := sendForm(server, url.Values{"bbs": {"news"}, "subject": {"検査"}, "MESSAGE": {"最初"}, "oimo_request_id": {"parallel-create-0001"}})
	if err != nil || !created.Accepted {
		t.Fatal(created, err)
	}
	b := repo.posting[info.ID]
	base := b.validateBase
	var fullCalls atomic.Int32
	stats := func() store.CommitStats {
		var sum store.CommitStats
		for _, j := range b.journals {
			s := j.CommitStats()
			sum.Syncs += s.Syncs
			sum.Writes += s.Writes
			sum.Bytes += s.Bytes
		}
		return sum
	}
	var before store.CommitStats
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		before = stats()
		b.validateBase = func(raw []byte) error {
			if err := base(raw); err != nil {
				return err
			}
			start := bytes.Index(raw, []byte(`"dedup":{`))
			if start < 0 {
				return nil
			}
			if fullCalls.Add(1) != 1 {
				return nil
			}
			key := []byte(`"subject_hmac":"`)
			offset := bytes.Index(raw[start:], key)
			if offset < 0 {
				return fmt.Errorf("missing dedup subject")
			}
			pos := start + offset + len(key)
			if raw[pos] == '0' {
				raw[pos] = '1'
			} else {
				raw[pos] = '0'
			}
			return nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fields := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"二番目"}, "oimo_request_id": {"parallel-reply-00001"}}
	rejected, err := sendForm(server, fields)
	if err != nil || rejected.Accepted {
		t.Fatal("bad capture accepted", rejected, err)
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		if fullCalls.Load() != 1 || stats() != before {
			t.Error("journal validation/write started before rejection", fullCalls.Load(), stats(), before)
		}
		if snap := b.threads[created.Key].SharedSnapshot(domain.Time(time.Now().UnixNano())); snap == nil || snap.PostCount != 1 {
			t.Error("private candidate published")
		}
		b.validateBase = base
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	retried, err := sendForm(server, fields)
	if err != nil || !retried.Accepted || retried.Number != 2 {
		t.Fatal("retry/order after rejection", retried, err)
	}
	if repo.memoryReserved.Load() != 0 || repo.postReserved != 0 {
		t.Fatal("candidate reservation leak")
	}
}
