// 案件の署名済み解除参照が、正当な古いactive正本と別の署名済み同seq解除を拒否することを検査する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// releasedOptionalProductFixture は元seq2の未保存状態から案件参照/解除参照まで署名し、旧active bytesも返す。
func releasedOptionalProductFixture(t *testing.T) (Config, *Repository, disclosure.Case, []byte) {
	t.Helper()
	cfg, r, c := terminalUnreflectedOptionalFixture(t)
	file := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, c.ID.String()+".json")
	active, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	c, e = r.reconcileTerminalOptionalHold(context.Background(), c, r.optionalStore)
	r.mu.Unlock()
	if e != nil || c.HTTP.Released == nil || c.HTTP.Released.Sequence != 3 {
		t.Fatal(c, e)
	}
	return cfg, r, c, active
}

func TestOptionalReleaseLedgerRejectsSignedActiveRollback(t *testing.T) {
	cfg, r, c, active := releasedOptionalProductFixture(t)
	file := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, c.ID.String()+".json")
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(file, active, 0600); e != nil {
		t.Fatal(e)
	}
	assertOptionalProductGuardRejects(t, cfg, file, active)
}

func TestOptionalReleaseLedgerRejectsDifferentSignedReleaseSameSequence(t *testing.T) {
	cfg, r, c, active := releasedOptionalProductFixture(t)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(cfg.DataDir, "reports", "http")
	file := filepath.Join(root, evidence.OptionalHoldsDirectory, c.ID.String()+".json")
	if e := os.WriteFile(file, active, 0600); e != nil {
		t.Fatal(e)
	}
	seed, e := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"))
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(key)
	source, e := evidence.OpenOptionalStore(root, c.HTTP.Site, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = source.ReleaseOptionalHoldChecked(context.Background(), *c.HTTP.Reservation, c.Revision, time.Now()); e != nil {
		t.Fatal(e)
	}
	alternative, _, e := source.OptionalHoldReceipt(c.ID)
	if e != nil || alternative.Sequence != c.HTTP.Released.Sequence || alternative.SHA == c.HTTP.Released.SHA {
		t.Fatal("different signed branch not created", alternative, e)
	}
	if _, e = source.CheckOptionalHoldReceipt(*c.HTTP.Reservation); e != nil {
		t.Fatal("alternative release was not a valid immediate source successor", e)
	}
	if e = source.Close(); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	assertOptionalProductGuardRejects(t, cfg, file, raw)
}

func TestOptionalReleaseLedgerRequiresSiteActivation(t *testing.T) {
	_, r, c, _ := releasedOptionalProductFixture(t)
	for _, missing := range []string{"optional_http:http", "optional_holds:http"} {
		state := r.site.State()
		state.Rows = maps.Clone(state.Rows)
		delete(state.Rows, missing)
		if e := requireOptionalHoldActivationForCases(state, []disclosure.Case{c}); !errors.Is(e, store.ErrCorrupt) {
			t.Fatal("case reference accepted without site activation", missing, e)
		}
	}
}

func TestOptionalReleaseLedgerRejectsWholeSetRollbackForLegacyUnboundCase(t *testing.T) {
	cfg, r, c, _, emptyIndex := optionalHeldCaseProductFixtureMode(t, false)
	r.mu.Lock()
	c, e := r.evidenceCases.Release(c.ID, c.Creator, c.ETag(), "legacy-unbound-cancel", "取消", time.Now())
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e = r.optionalStore.ReleaseOptionalHold(context.Background(), c.ID, c.Revision, time.Now()); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	c, e = r.reconcileTerminalOptionalHold(context.Background(), c, r.optionalStore)
	r.mu.Unlock()
	if e != nil || c.HTTP.Reservation != nil || c.HTTP.Released == nil {
		t.Fatal(c, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory)
	if e = os.Remove(filepath.Join(root, c.ID.String()+".json")); e != nil {
		t.Fatal(e)
	}
	index := filepath.Join(root, evidence.OptionalHoldIndexFile)
	if e = os.WriteFile(index, emptyIndex, 0600); e != nil {
		t.Fatal(e)
	}
	assertOptionalProductGuardRejects(t, cfg, index, emptyIndex)
}
