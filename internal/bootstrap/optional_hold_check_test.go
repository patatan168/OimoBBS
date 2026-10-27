// 製品check/startupで案件の元参照巻戻し・孤立予約を拒否し、原本fileを保持することを検査する。
package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

// optionalHeldCaseProductFixture は実フォームの受理証拠を案件へ保全し、元予約参照まで同期する。
func optionalHeldCaseProductFixture(t *testing.T) (Config, *Repository, disclosure.Case, []evidence.Entry, []byte) {
	return optionalHeldCaseProductFixtureMode(t, true)
}

// optionalHeldCaseProductFixtureMode は参照保存前のreader42停止点も実製品の固定intentから作る。
func optionalHeldCaseProductFixtureMode(t *testing.T, bind bool) (Config, *Repository, disclosure.Case, []evidence.Entry, []byte) {
	t.Helper()
	cfg, r := optionalHoldProductFixture(t)
	b, e := r.CreateBoard(context.Background(), "holdproof", "予約照合")
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	if e = r.ensureOptionalHoldStorage(context.Background()); e != nil {
		t.Fatal(e)
	}
	emptyIndex, e := os.ReadFile(filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, evidence.OptionalHoldIndexFile))
	if e != nil {
		t.Fatal(e)
	}
	fs := formServer(t, r, siteID(r.site.State()), b.ID)
	posted, e := sendForm(fs, url.Values{"bbs": {"holdproof"}, "subject": {"照合"}, "MESSAGE": {"証拠投稿"}, "oimo_request_id": {"holdproof-create-01"}})
	fs.Close()
	if e != nil || !posted.Accepted {
		t.Fatal(posted, e)
	}
	now := time.Now()
	c := disclosure.Case{Number: "SOURCE-PROOF", Reason: "起動照合", Scope: disclosure.Scope{Board: b.ID, Thread: domain.U64(posted.Key), From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano())}}
	r.mu.Lock()
	defer r.mu.Unlock()
	actor := domain.NewID()
	c, e = r.evidenceCases.Create(c, actor, `"evidence:new"`, "holdproof-case", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	accepted, e := r.collectEvidence(context.Background(), c.Scope)
	if e != nil || len(accepted) != 1 {
		t.Fatal(len(accepted), e)
	}
	c, e = r.evidenceCases.Hold(c.ID, actor, c.ETag(), "holdproof-required", "保全", accepted, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	op := accepted[0].Operation
	record := evidence.OptionalRecord{Schema: "optional-http-v1", FinishStage: "handler_return", UAStatus: "captured", ID: domain.NewID(), Site: siteID(r.site.State()), Boot: domain.NewID(), Connection: domain.NewID(), Request: domain.NewID(), Received: accepted[0].Committed, Finished: accepted[0].Committed + 100, Until: accepted[0].Committed + domain.Time(evidence.OptionalRetention), Peer: evidence.Endpoint{IP: "192.0.2.1", Port: 12345}, Local: evidence.Endpoint{IP: "192.0.2.2", Port: 443}, Method: "POST", Route: "legacy_post", Kind: "response", Outcome: "accepted", Status: 200, HTTPVersion: "HTTP/1.1", Board: &b.ID, Operation: &op}
	if e = r.optionalStore.Write(context.Background(), record); e != nil {
		t.Fatal(e)
	}
	entries, e := r.optionalStore.QuerySigned(context.Background(), evidence.OptionalQueryScope{Board: b.ID, From: c.Scope.From, To: c.Scope.To, Operations: []domain.ID{op}}, time.Now())
	if e != nil || len(entries) != 1 {
		t.Fatal(len(entries), e)
	}
	c, e = r.evidenceCases.PrepareHTTPHold(c.ID, actor, c.ETag(), "holdproof-http", "HTTP保全", record.Site, entries, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	binding, e := r.evidenceCases.HTTPReservationBinding(c, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = r.optionalStore.ReserveOptionalHold(context.Background(), binding, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	ref, _, e := r.optionalStore.OptionalHoldReceipt(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if bind {
		c, e = r.evidenceCases.BindHTTPReservation(c.ID, actor, c.ETag(), ref, time.Now())
		if e != nil {
			t.Fatal(e)
		}
	}
	return cfg, r, c, entries, emptyIndex
}

func TestOptionalHoldStartupRejectsSignedSourceRollback(t *testing.T) {
	cfg, r, c, entries, _ := optionalHeldCaseProductFixture(t)
	file := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, c.ID.String()+".json")
	old, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	b, e := r.evidenceCases.HTTPReservationBinding(c, time.Now())
	if e == nil {
		e = r.optionalStore.ReserveOptionalHold(context.Background(), b, entries, time.Now())
	}
	ref, _, getError := r.optionalStore.OptionalHoldReceipt(c.ID)
	if e == nil {
		e = getError
	}
	if e == nil {
		c, e = r.evidenceCases.BindHTTPReservation(c.ID, c.Creator, c.ETag(), ref, time.Now())
	}
	r.mu.Unlock()
	if e != nil || ref.Sequence != 2 {
		t.Fatal(ref.Sequence, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, old, 0600); e != nil {
		t.Fatal(e)
	}
	assertOptionalProductGuardRejects(t, cfg, file, old)
}

func TestOptionalHoldStartupRejectsOrphanReservation(t *testing.T) {
	cfg, r, c, entries, _ := optionalHeldCaseProductFixture(t)
	b := c.HTTP.Reservation.Binding
	b.Case = domain.NewID()
	if e := r.optionalStore.ReserveOptionalHold(context.Background(), b, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, b.Case.String()+".json")
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	assertOptionalProductGuardRejects(t, cfg, file, raw)
}

// assertOptionalProductGuardRejects は読取り検査/製品起動が同じ不整合を拒否し、元予約を変更しないことを確認する。
func assertOptionalProductGuardRejects(t *testing.T, cfg Config, file string, before []byte) {
	t.Helper()
	lock, e := platform.Lock(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	_, checkError := checkLockedPosting(cfg, false, true)
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	if !errors.Is(checkError, store.ErrCorrupt) {
		t.Fatal("posting-aware read-only check accepted source mismatch", checkError)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e == nil {
		reopened.Close()
		t.Fatal("startup accepted source mismatch")
	}
	if !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("startup rejection", e)
	}
	after, e := os.ReadFile(file)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected source file changed", e)
	}
}

func TestOptionalHoldStartupRejectsWholeSetRollbackToEmpty(t *testing.T) {
	cfg, r, c, _, emptyIndex := optionalHeldCaseProductFixture(t)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory)
	if e := os.Remove(filepath.Join(root, c.ID.String()+".json")); e != nil {
		t.Fatal(e)
	}
	index := filepath.Join(root, evidence.OptionalHoldIndexFile)
	if e := os.WriteFile(index, emptyIndex, 0600); e != nil {
		t.Fatal(e)
	}
	assertOptionalProductGuardRejects(t, cfg, index, emptyIndex)
}

func TestOptionalHoldStartupRejectsReleaseBeforeCopyOrCancel(t *testing.T) {
	cfg, r, c, _, _ := optionalHeldCaseProductFixture(t)
	if e := r.optionalStore.ReleaseOptionalHold(context.Background(), c.ID, c.Revision, time.Now()); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, c.ID.String()+".json")
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	assertOptionalProductGuardRejects(t, cfg, file, raw)
}

func TestOptionalHoldStartupAcceptsBoundOrUnreflectedNext(t *testing.T) {
	for _, next := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "next"}[next], func(t *testing.T) {
			cfg, r, c, entries, _ := optionalHeldCaseProductFixture(t)
			if next {
				r.mu.Lock()
				b, e := r.evidenceCases.HTTPReservationBinding(c, time.Now())
				if e == nil {
					e = r.optionalStore.ReserveOptionalHold(context.Background(), b, entries, time.Now())
				}
				r.mu.Unlock()
				if e != nil {
					t.Fatal(e)
				}
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("valid incomplete copy rejected at startup", e)
			}
			defer reopened.Close()
			found, e := reopened.optionalStore.QueryOptionalHold(context.Background(), c.ID, time.Now())
			if e != nil || len(found) != 1 || found[0].Event.EventSHA != entries[0].Event.EventSHA {
				t.Fatal("protected original unavailable", found, e)
			}
			ref, exists, e := reopened.optionalStore.OptionalHoldReceipt(c.ID)
			if e != nil || !exists || ref.Sequence != c.HTTP.Reservation.Sequence+domain.U64(map[bool]int{false: 0, true: 1}[next]) {
				t.Fatal(ref, exists, e)
			}
		})
	}
}
