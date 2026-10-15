// 実Repositoryのreader先行Sync・板所有列初期化・起動前の署名集合照合と欠落拒否を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

func requiredHoldStorageFixture(t *testing.T) (Config, *Repository, domain.ID) {
	t.Helper()
	cfg, r := adminFixture(t)
	b, e := r.CreateBoard(t.Context(), "requiredlog", "必須予約")
	if e != nil {
		r.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = r.Close() })
	return cfg, r, b.ID
}

func TestRequiredHoldStorageActivationAndReopen(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- r.ensureRequiredHoldStorage(t.Context(), id) }()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	state := r.site.State()
	var site siteState
	if e := strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil || site.MinimumReader != 46 {
		t.Fatal(site, e)
	}
	a, e := decodeRequiredHoldActivation(id.String(), state.Rows["required_holds:"+id.String()].Value)
	if e != nil || a.Phase != "active" {
		t.Fatal(a, e)
	}
	b := r.posting[id]
	if b.requiredHolds == nil {
		t.Fatal("owner storage absent")
	}
	inspection, e := app.InspectRequiredOriginalHolds(requiredHoldStoragePath(cfg.DataDir, id), id, 10, b.key)
	if e != nil || len(inspection.Receipts) != 0 || inspection.Floor == 0 {
		t.Fatal(inspection, e)
	}
	seq := state.Seq
	if e = r.ensureRequiredHoldStorage(t.Context(), id); e != nil || r.site.State().Seq != seq {
		t.Fatal("activation replay wrote state", e)
	}
	if boards, e := backupRequiredBoards(state, site.ID); e != nil || len(boards) != 1 || boards[0] != id {
		t.Fatal("backup reservation boundary missing", boards, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	if _, e = Check(cfg); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("check changed initialized empty storage")
	}
	r2, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer r2.Close()
	if r2.posting[id].requiredHolds == nil {
		t.Fatal("reopen lost required table")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("reopen rewrote initialized empty storage")
	}
}

func TestRequiredHoldStoragePreparingRecovery(t *testing.T) {
	for _, stage := range []string{"before_parent", "before_control", "after_control", "creation_intent", "partial_wal"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, id := requiredHoldStorageFixture(t)
			r.mu.Lock()
			b, _, e := r.prepareRequiredHoldStorageLocked(t.Context(), id)
			r.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			if stage != "before_parent" {
				_, e = b.worker.Submit(t.Context(), func() (any, error) { return nil, b.initializeRequiredHoldStorage(false) })
				if e != nil {
					t.Fatal(e)
				}
				if stage == "before_control" || stage == "creation_intent" || stage == "partial_wal" {
					wal := filepath.Join(requiredHoldStoragePath(cfg.DataDir, id), "control-000001.wal")
					original, e := os.ReadFile(wal)
					if e != nil {
						t.Fatal(e)
					}
					if e = b.requiredHolds.Close(); e != nil {
						t.Fatal(e)
					}
					b.requiredHolds = nil
					if stage != "before_control" {
						intent := filepath.Join(filepath.Dir(requiredHoldStoragePath(cfg.DataDir, id)), "."+id.String()+".create.frame")
						if e = os.WriteFile(intent, original[store.HeaderSize:], 0600); e != nil {
							t.Fatal(e)
						}
					}
					if stage == "partial_wal" {
						if e = os.Remove(filepath.Join(requiredHoldStoragePath(cfg.DataDir, id), "control.current")); e != nil {
							t.Fatal(e)
						}
						if e = os.WriteFile(wal, original[:40], 0600); e != nil {
							t.Fatal(e)
						}
					} else if e = os.RemoveAll(requiredHoldStoragePath(cfg.DataDir, id)); e != nil {
						t.Fatal(e)
					}
				}

			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			if _, e = Check(cfg); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("pending check did not refuse", e)
			}
			if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
				t.Fatal("pending check modified source")
			}
			r2, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			defer r2.Close()
			a, e := decodeRequiredHoldActivation(id.String(), r2.site.State().Rows["required_holds:"+id.String()].Value)
			if e != nil || a.Phase != "active" || r2.posting[id].requiredHolds == nil {
				t.Fatal(a, e)
			}
		})
	}
}

func TestRequiredHoldStorageActiveMissingOrUnknownRefusal(t *testing.T) {
	for _, stage := range []string{"missing_empty_table", "unknown_owner", "unknown_file", "future_floor"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, id := requiredHoldStorageFixture(t)
			if stage == "future_floor" {
				r.posting[id].clock = func() time.Time { return time.Now().Add(time.Hour) }
			}
			if e := r.ensureRequiredHoldStorage(t.Context(), id); e != nil {
				t.Fatal(e)
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			root := filepath.Join(cfg.DataDir, "reports", requiredHoldStorageDirectory)
			switch stage {
			case "missing_empty_table":
				if e := os.RemoveAll(filepath.Join(root, id.String())); e != nil {
					t.Fatal(e)
				}
			case "unknown_owner":
				if e := os.Mkdir(filepath.Join(root, domain.NewID().String()), 0700); e != nil {
					t.Fatal(e)
				}
			case "unknown_file":
				if e := os.WriteFile(filepath.Join(root, "unknown"), []byte("unknown"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			if _, e := Check(cfg); e == nil {
				t.Fatal("check accepted invalid required table")
			}
			if opened, e := OpenPostingRepository(cfg, postcapture.Validate); e == nil {
				opened.Close()
				t.Fatal("open repaired active missing/unknown/future table")
			}
			if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
				t.Fatal("failed check/open changed bytes")
			}
		})
	}
}

func productRequiredReservation(t *testing.T, r *Repository, id domain.ID) (disclosure.Case, app.RequiredHoldReceipt, []app.AcceptedEvidence) {
	t.Helper()
	if e := r.ensureRequiredHoldStorage(t.Context(), id); e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), id)
	posted, e := sendForm(server, url.Values{"bbs": {"requiredlog"}, "subject": {"原本照合"}, "MESSAGE": {"required-source-test"}, "oimo_request_id": {"required-test-001"}})
	server.Close()
	if e != nil || !posted.Accepted {
		t.Fatal(posted, e)
	}
	now := time.Now()
	scope := disclosure.Scope{Board: id, Thread: domain.U64(posted.Key), From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano()), Records: []domain.ID{}}
	actor := domain.NewID()
	r.mu.Lock()
	rows, e := r.collectEvidence(context.Background(), scope)
	if e != nil {
		r.mu.Unlock()
		t.Fatal(e)
	}
	c, e := r.evidenceCases.Create(disclosure.Case{Number: "required-product", Reason: "原本保全", Scope: scope, Until: domain.Time(now.Add(24 * time.Hour).UnixNano())}, actor, `"evidence:new"`, "create", now)
	if e == nil {
		c, e = r.evidenceCases.PrepareHold(c.ID, actor, c.ETag(), "hold", "原本保全", rows, now)
	}
	var binding app.RequiredHoldBinding
	if e == nil {
		binding, e = r.evidenceCases.RequiredReservationBinding(c, now)
	}
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	b := r.posting[id]
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		return b.requiredHolds.Reserve(binding, rows, b.journals, domain.Time(time.Now().UnixNano()))
	})
	if e != nil {
		t.Fatal(e)
	}
	receipt := value.(app.RequiredHoldReceipt)
	return c, receipt, rows
}

func TestRequiredHoldProductGuardAcrossUnreflectedAndBoundCase(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	c, receipt, _ := productRequiredReservation(t, r, id)
	r.mu.Lock()
	var site siteState
	e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site)
	if e == nil {
		e = inspectRequiredHoldStorage(cfg, site, r.site.State(), false)
	}
	if e == nil {
		c, e = r.evidenceCases.BindRequiredReservation(c.ID, c.Creator, c.ETag(), receipt, time.Now())
	}
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	if _, e = checkLockedPosting(cfg, false, true); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("cross check changed original")
	}
	r2, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer r2.Close()
	if got, e := r2.evidenceCases.Get(c.ID); e != nil || got.Required == nil {
		t.Fatal(got, e)
	}
}

func TestRequiredHoldActivationValidation(t *testing.T) {
	site, board := domain.NewID(), domain.NewID()
	preparing := requiredHoldActivation{Schema: requiredHoldActivationSchema, Site: site, Board: board, Phase: "preparing"}
	raw, _ := json.Marshal(preparing)
	active := preparing
	active.Phase = "active"
	next, _ := json.Marshal(active)
	if e := validateRequiredHoldActivation(board.String(), nil, raw); e != nil {
		t.Fatal(e)
	}
	if e := validateRequiredHoldActivation(board.String(), raw, next); e != nil {
		t.Fatal(e)
	}
	if e := snapshotSiteValue("required_holds", board.String(), nil, next); e != nil {
		t.Fatal(e)
	}
	for _, pair := range [][2]json.RawMessage{{nil, next}, {next, raw}, {next, next}, {raw, json.RawMessage(`null`)}} {
		if e := validateRequiredHoldActivation(board.String(), pair[0], pair[1]); e == nil {
			t.Fatal("invalid activation transition")
		}
	}
	if e := validateRequiredHoldActivation(domain.NewID().String(), nil, raw); e == nil {
		t.Fatal("owner key mismatch")
	}
}

func TestRequiredHoldStorageOptionalPreparingCoexistence(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	if e := r.ensureRequiredHoldStorage(t.Context(), id); e != nil {
		t.Fatal(e)
	}
	a := optionalLogActivation{Schema: "optional-http-activation-v1", Site: siteID(r.site.State()), Phase: "preparing"}
	if e := appendControl(r.site, "optional_http_prepare", []store.Mutation{mutation("optional_http", "http", a, nil)}, []string{}); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	r2, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer r2.Close()
	if r2.optionalStore == nil || r2.posting[id].requiredHolds == nil {
		t.Fatal("one private source prevented other preparation")
	}
}

func TestRequiredHoldProductGuardRefusesSourceLossAndPrematureRelease(t *testing.T) {
	for _, stage := range []string{"missing_original", "missing_reservation", "premature_release", "orphan_source"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, id := requiredHoldStorageFixture(t)
			c, receipt, records := productRequiredReservation(t, r, id)
			r.mu.Lock()
			c, e := r.evidenceCases.BindRequiredReservation(c.ID, c.Creator, c.ETag(), receipt, time.Now())
			r.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			b := r.posting[id]
			if stage == "premature_release" || stage == "orphan_source" {
				_, e = b.worker.Submit(t.Context(), func() (any, error) {
					if stage == "premature_release" {
						return b.requiredHolds.Release(receipt, domain.Time(time.Now().UnixNano()))
					}
					binding := receipt.Binding
					binding.Case = domain.NewID()
					return b.requiredHolds.Reserve(binding, records, b.journals, domain.Time(time.Now().UnixNano()))
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			if stage == "missing_original" {
				path := filepath.Join(cfg.DataDir, "evidence", id.String(), strconv.FormatUint(uint64(receipt.Postings[0].Proposal.Day), 10))
				if e = os.RemoveAll(path); e != nil {
					t.Fatal(e)
				}
			}
			if stage == "missing_reservation" {
				if e = os.RemoveAll(requiredHoldStoragePath(cfg.DataDir, id)); e != nil {
					t.Fatal(e)
				}
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			if _, e = checkLockedPosting(cfg, false, true); e == nil {
				t.Fatal("check accepted broken source/case", c.ID)
			}
			if opened, e := OpenPostingRepository(cfg, postcapture.Validate); e == nil {
				opened.Close()
				t.Fatal("open repaired broken source/case", c.ID)
			}
			if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
				t.Fatal("guard failure changed source/case bytes")
			}
		})
	}
}

func TestRequiredHoldProductOriginalPositionInspection(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	_, receipt, _ := productRequiredReservation(t, r, id)
	b := r.posting[id]
	before := requiredStartupFiles(t, cfg.DataDir)
	if e := inspectRequiredHeldOriginals(cfg.DataDir, b.key, []app.RequiredHoldReceipt{receipt}, domain.Time(time.Now().UnixNano())); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"sequence", "hash", "day"} {
		changed := receipt
		changed.Postings = append([]app.RequiredHeldPosting{}, receipt.Postings...)
		switch field {
		case "sequence":
			changed.Postings[0].Decision.Sequence++
		case "hash":
			changed.Postings[0].Identity.DecisionSHA[0] ^= 1
		case "day":
			changed.Postings[0].Decision.Day = 20000101
		}
		if e := inspectRequiredHeldOriginals(cfg.DataDir, b.key, []app.RequiredHoldReceipt{changed}, domain.Time(time.Now().UnixNano())); e == nil {
			t.Fatal("original position change accepted", field)
		}
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("position inspection changed files")
	}
}

func TestRequiredHoldProductSignedSourceRollbackRefusal(t *testing.T) {
	for _, kind := range []string{"rollback", "copy_loss"} {
		t.Run(kind, func(t *testing.T) { testRequiredHoldProductReleaseIntegrity(t, kind) })
	}
}

func testRequiredHoldProductReleaseIntegrity(t *testing.T, kind string) {
	t.Helper()
	cfg, r, id := requiredHoldStorageFixture(t)
	c, receipt, records := productRequiredReservation(t, r, id)
	b := r.posting[id]
	r.mu.Lock()
	c, e := r.evidenceCases.BindRequiredReservation(c.ID, c.Creator, c.ETag(), receipt, time.Now())
	if e == nil {
		check := func() error {
			_, e := b.worker.Submit(t.Context(), func() (any, error) {
				return b.requiredHolds.Fetch(receipt, b.journals, domain.Time(time.Now().UnixNano()))
			})
			return e
		}
		c, e = r.evidenceCases.ResumeRequiredReserved(c.ID, c.Creator, c.ETag(), records, receipt, time.Now(), check)
	}
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	path := requiredHoldStoragePath(cfg.DataDir, id)
	old := requiredStartupFiles(t, path)
	value, e := b.worker.Submit(t.Context(), func() (any, error) { return b.requiredHolds.Release(receipt, domain.Time(time.Now().UnixNano())) })
	if e != nil {
		t.Fatal(e)
	}
	released := value.(app.RequiredHoldReceipt)
	r.mu.Lock()
	c, e = r.evidenceCases.RecordRequiredRelease(c.ID, c.Creator, c.ETag(), released, time.Now())
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = checkLockedPosting(cfg, false, true); e != nil {
		t.Fatal("valid release/copy rejected", e)
	}
	if kind == "rollback" {
		for name, raw := range old {
			if e = os.WriteFile(name, raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
	} else {
		for _, item := range c.Items {
			path := filepath.Join(cfg.DataDir, "cases", c.ID.String(), "items", item.Record.String()+".json")
			if e = os.Remove(path); e != nil {
				t.Fatal(e)
			}
		}
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	if _, e = checkLockedPosting(cfg, false, true); e == nil {
		t.Fatal("invalid release/copy accepted", kind)
	}
	if opened, e := OpenPostingRepository(cfg, postcapture.Validate); e == nil {
		opened.Close()
		t.Fatal("invalid release/copy repaired", kind)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("release/copy refusal changed files", kind)
	}
}
