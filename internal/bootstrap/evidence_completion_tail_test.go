// 旧4096行案件を実製品起動でreader先行保存して閉じ、低readerでの非変更拒否を検証する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestCaseCompletionTailProductStartupAndReopen(t *testing.T) {
	cfg, r := adminFixture(t)
	b, e := r.CreateBoard(t.Context(), "tail", "終端")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.enableStorageReader(t.Context(), 38, "evidence_cases_enable"); e != nil {
		t.Fatal(e)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	actor := domain.NewID()
	input := disclosure.Case{Number: "legacy-full", Reason: "fixture", Scope: disclosure.Scope{Board: b.ID, From: domain.Time(old.Add(-time.Hour).UnixNano()), To: domain.Time(old.UnixNano())}}
	c, e := r.evidenceCases.Create(input, actor, `"evidence:new"`, "legacy-full-case", old)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	fillLegacyCaseControl(t, cfg, c, actor, old)
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	checkProductCompletedCase(t, reopened, c)
	if e = reopened.Close(); e != nil {
		t.Fatal(e)
	}
	checkProductTailReopenAndReaderRefusal(t, cfg, c)
}

// fillLegacyCaseControl は署名済み試験履歴を一行Control frameで旧上限まで耐久保存する。
func fillLegacyCaseControl(t *testing.T, cfg Config, c disclosure.Case, actor domain.ID, at time.Time) {
	t.Helper()
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	path := filepath.Join(cfg.DataDir, "cases", c.ID.String(), "control")
	log, e := store.OpenControl(path, 9, c.ID, 0, func(_, _ string, _, next json.RawMessage) error { return strictjson.Validate(next) })
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	var previous evidence.Event
	for _, row := range log.State().Rows {
		if row.Revision != log.State().Seq {
			continue
		}
		if e = json.Unmarshal(row.Value, &previous); e != nil {
			t.Fatal(e)
		}
	}
	for seq := uint64(log.State().Seq) + 1; seq <= disclosure.MaxCaseAudits; seq++ {
		c.Revision = domain.U64(seq)
		raw, event := legacyCaseControlFrame(t, c, actor, at, key, previous.EventSHA)
		if result := log.Append(raw); result.Status != store.Durable {
			t.Fatal(result)
		}
		previous = event
	}
}

func legacyCaseControlFrame(t *testing.T, c disclosure.Case, actor domain.ID, at time.Time, key ed25519.PrivateKey, previous domain.Hash) ([]byte, evidence.Event) {
	t.Helper()
	a := disclosure.Audit{Owner: c.ID, Seq: c.Revision, At: domain.Time(at.UnixNano()), Actor: actor, Action: "query", Purpose: "legacy capacity fixture", Columns: []string{}, Case: c}
	payload, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	event, e := evidence.Seal(evidence.Source{Owner: c.ID, Seq: uint64(c.Revision)}, domain.NewID(), "receipt", payload, previous, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	value, e := json.Marshal(event)
	if e != nil {
		t.Fatal(e)
	}
	kid, request := uint32(10), domain.Hash{1}
	op := store.ControlOperation{Schema: 1, Seq: c.Revision, ExpectedSeq: c.Revision - 1, Committed: a.At, Actor: domain.Actor{Kind: "admin", ID: &actor, Reason: "evidence_query", Request: &request, Idempotency: &request, KeyID: &kid}, Mutations: []store.Mutation{{Collection: "transfer", Key: event.RecordID.String(), Value: value}}, Result: store.ControlResult{Code: "evidence_saved", Targets: []string{c.ID.String()}}}
	body, e := json.Marshal(op)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(c.Revision), Records: []store.Record{{ID: event.RecordID, JSON: body}}})
	if e != nil {
		t.Fatal(e)
	}
	return raw, event
}

func checkProductCompletedCase(t *testing.T, r *Repository, c disclosure.Case) {
	t.Helper()
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	if site.MinimumReader != 49 {
		t.Fatal("tail reader not saved", site.MinimumReader)
	}
	latest, e := r.evidenceCases.Get(c.ID)
	if e != nil || latest.State != "closed" || uint64(latest.Revision) != disclosure.MaxCaseAudits+2 {
		t.Fatal(latest, e)
	}
}

func checkProductTailReopenAndReaderRefusal(t *testing.T, cfg Config, c disclosure.Case) {
	t.Helper()
	r, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	checkProductCompletedCase(t, r, c)
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	seed, e := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	before := requiredStartupFiles(t, cfg.DataDir)
	if e = disclosure.InspectVersion(filepath.Join(cfg.DataDir, "cases"), key, 48); e == nil {
		t.Fatal("reader48 accepted saved tail")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("low reader altered history")
	}
}

func TestCaseCompletionPreparationStoppedIsNonMutating(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	before := requiredStartupFiles(t, cfg.DataDir)
	r.mu.Lock()
	r.stopped = true
	e := r.prepareCaseCompletionTailLocked(time.Now())
	r.stopped = false
	r.mu.Unlock()
	if e == nil {
		t.Fatal("stopped repository prepared tail")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("stopped preparation changed storage")
	}
}
