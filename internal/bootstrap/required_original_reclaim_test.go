// 実Repositoryの完了task/共有容量/署名保護を通し、期限切れ原本を回収して再起動する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func expiredRequiredFrame(t *testing.T) ([]byte, domain.Time) {
	t.Helper()
	f, _, e := store.ReadFrame(bytes.NewReader(persistentFrame(t)))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	var create domain.Create
	if e = json.Unmarshal(op.Payload, &create); e != nil {
		t.Fatal(e)
	}
	at := domain.Time(time.Now().AddDate(-1, 0, 0).UnixNano())
	op.Committed, op.After.LastUserAt, op.Dedup.Expires = at, at, at+86400e9
	create.Created, create.Posts[0].Created = at, at
	create.Expires = domain.Time(domain.SixMonths(time.Unix(0, int64(at))).UnixNano())
	op.Payload, _ = json.Marshal(create)
	f.Records[0].JSON, _ = json.Marshal(op)
	raw, e := store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	return raw, at
}

func TestRequiredOriginalRepositoryRejectsMissingActivatedSource(t *testing.T) {
	cfg, r, id, key, day, i := requiredReclaimRepositoryFixture(t, true)
	if e := r.ensureRequiredHoldStorage(t.Context(), id); e != nil {
		t.Fatal(e)
	}
	path := requiredHoldStoragePath(cfg.DataDir, id)
	saved := filepath.Join(cfg.DataDir, "reports", ".saved-required-source")
	if e := os.Rename(path, saved); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = os.Rename(saved, path) }()
	before := requiredStartupFiles(t, cfg.DataDir)
	if n, e := r.ReclaimRequiredOriginals(t.Context(), id, key, day, []evidence.RequiredPostingIdentity{i}); e == nil || n != 0 {
		t.Fatal("missing activated source allowed GC", n, e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) || r.postReserved != 0 {
		t.Fatal("failed source inspection changed storage")
	}
}

func TestRequiredOriginalRepositoryChangedCandidateKeepsOwnerAvailable(t *testing.T) {
	cfg, r, id, key, day, i := requiredReclaimRepositoryFixture(t, true)
	before := requiredStartupFiles(t, cfg.DataDir)
	i.DecisionSHA[0] ^= 1
	if n, e := r.ReclaimRequiredOriginals(t.Context(), id, key, day, []evidence.RequiredPostingIdentity{i}); !errors.Is(e, app.ErrEvidenceGap) || n != 0 {
		t.Fatal(n, e)
	}
	if r.posting[id].stopped || r.postReserved != 0 || !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("invalid candidate changed or stopped owner")
	}
}

func requiredReclaimRepositoryFixture(t *testing.T, complete bool) (Config, *Repository, domain.ID, uint64, uint64, evidence.RequiredPostingIdentity) {
	t.Helper()
	cfg, r, info := postingRepositoryFixture(t)
	if _, e := r.ConfigureAdministrator("owner", "所有者", adminTestSecret, false); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	r, e = OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = r.Close() })
	if e := r.EnablePublicBodyReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	b := r.posting[info.ID]
	// 個別回収の非変更検査へ、既存の自動期限掃除が割り込まないよう終了を待つ。
	b.expiryCancel()
	<-b.expiryDone
	if _, e := r.enableStorageReader(t.Context(), 45, "required_original_reclaim_test_enable"); e != nil {
		t.Fatal(e)
	}
	frame, at := expiredRequiredFrame(t)
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return time.Unix(0, int64(at)) }
		defer func() { b.clock = time.Now }()
		return b.post(0, frame, []byte(`{"fixture":true}`)), nil
	})
	if e != nil || value.(RepositoryPostingResult).Status != store.Durable {
		t.Fatal(value, e)
	}
	key := value.(RepositoryPostingResult).ThreadKey
	if complete {
		if e := r.ReclaimPublicBodies(t.Context(), 1); e != nil {
			t.Fatal(e)
		}
	}
	day, identity := requiredReclaimIdentity(t, b)
	return cfg, r, info.ID, key, day, identity
}

func requiredReclaimIdentity(t *testing.T, b *postingBoard) (uint64, evidence.RequiredPostingIdentity) {
	t.Helper()
	var day uint64
	var identity evidence.RequiredPostingIdentity
	_, e := b.worker.Submit(t.Context(), func() (any, error) {
		for d, j := range b.journals {
			rows, e := app.AcceptedRecords([]*evidence.Journal{j})
			if e != nil {
				return nil, e
			}
			if len(rows) == 1 {
				identity, e = app.PostingRetirementIdentity(rows[0].Proposal, rows[0].Decision)
				day = d
				return nil, e
			}
		}
		return nil, app.ErrEvidenceGap
	})
	if e != nil {
		t.Fatal(e)
	}
	return day, identity
}

func TestRequiredOriginalRepositoryReclaimAndReopen(t *testing.T) {
	cfg, r, board, key, day, i := requiredReclaimRepositoryFixture(t, true)
	requiredReclaimDraft(t, r, board)
	n, e := r.ReclaimRequiredOriginals(t.Context(), board, key, day, []evidence.RequiredPostingIdentity{i})
	if e != nil || n != 2 {
		t.Fatal(n, e)
	}
	if r.postReserved != 0 {
		t.Fatal("capacity reservation leaked")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	before := requiredStartupFiles(t, cfg.DataDir)
	if n, e = reopened.ReclaimRequiredOriginals(t.Context(), board, key, day, []evidence.RequiredPostingIdentity{i}); e != nil || n != 0 {
		t.Fatal("repeat mutated", n, e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("repeat changed original files")
	}
}

func requiredReclaimDraft(t *testing.T, r *Repository, id domain.ID) {
	t.Helper()
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	_, e := r.evidenceCases.Create(disclosure.Case{Number: "gc-draft", Reason: "原本回収時の案件照合", Scope: disclosure.Scope{Board: id, From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano())}, Until: domain.Time(now.Add(time.Hour).UnixNano())}, domain.NewID(), `"evidence:new"`, "gc-draft-create", now)
	if e != nil {
		t.Fatal(e)
	}
}

func TestRequiredOriginalRepositoryRejectsIncompleteTaskAndSharedCapacity(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "incomplete_task", true: "capacity_reserved"}[complete], func(t *testing.T) {
			cfg, r, board, key, day, i := requiredReclaimRepositoryFixture(t, complete)
			before := requiredStartupFiles(t, cfg.DataDir)
			if complete {
				r.packSpace = func(string) (platform.DiskSpace, error) {
					return platform.DiskSpace{Total: 1 << 30, Available: 4 << 20}, nil
				}
				r.backupReserved = 4 << 20
				defer func() { r.backupReserved = 0 }()
			}
			n, e := r.ReclaimRequiredOriginals(t.Context(), board, key, day, []evidence.RequiredPostingIdentity{i})
			if e == nil || n != 0 || r.postReserved != 0 {
				t.Fatal(n, e)
			}
			if complete && !errors.Is(e, ErrPostingCapacity) {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
				t.Fatal("rejected GC changed storage")
			}
		})
	}
}
