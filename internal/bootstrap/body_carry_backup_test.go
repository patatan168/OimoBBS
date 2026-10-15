// 満了carryの部分削除/初回snapshotを既存backupへ含め、隔離再生で復活しないことを検査する。
package bootstrap

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func TestBodyCarryBackupPartialAndSnapshotReplay(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		t.Run(fmt.Sprint(snapshot), func(t *testing.T) { checkCarryBackup(t, snapshot) })
	}
}

// checkCarryBackup は実満了正本を部分削除/圧縮してオンラインと停止中copyを検査する。
func checkCarryBackup(t *testing.T, snapshot bool) {
	t.Helper()
	cfg, r, owner, key, day, identity := requiredReclaimRepositoryFixture(t, true)
	limit := 1
	if snapshot {
		limit = 128
	}
	if _, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, limit); e != nil {
		t.Fatal(e)
	}
	requiredReclaimDraft(t, r, owner)
	if n, e := r.ReclaimRequiredOriginals(t.Context(), owner, key, day, []evidence.RequiredPostingIdentity{identity}); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	if snapshot {
		if e := r.CompactExpiredBodyCarry(t.Context(), owner, key); e != nil {
			t.Fatal(e)
		}
	}
	if snapshot {
		assertCarrySiteBackup(t, r, owner, key)
	}
	expected := r.posting[owner].deletions[key].State()
	public := r.posting[owner].key.Public().(ed25519.PublicKey)
	assertCarryOnlineBackup(t, r, owner, key, expected, snapshot)
	e := r.Close()
	if e != nil {
		t.Fatal(e)
	}
	checkOfflineCarryBackup(t, cfg, owner, key, expected, public)
}

// captureCarryOfflineFixture は起動時保守後の固定署名を照合し、正本を利用不能にする。
func captureCarryOfflineFixture(t *testing.T, cfg Config, owner domain.ID, key uint64, expected store.ControlState) (string, string, string, store.ControlState) {
	t.Helper()
	var e error
	parent := candidateParent(t)
	body, keys, work := filepath.Join(parent, "body"), filepath.Join(parent, "keys"), filepath.Join(parent, "work")
	if _, e = CaptureOfflineBackup(t.Context(), cfg, body); e != nil {
		t.Fatal("offline carry capture", e)
	}
	source := filepath.Join(cfg.DataDir, "expiry", owner.String(), fmt.Sprint(key))
	current, e := inspectDeletionControl(source, owner, key)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(current.Rows["reclamation:carry_retirement"], expected.Rows["reclamation:carry_retirement"]) {
		t.Fatal("backup startup changed fixed signature")
	}
	assertCarrySourceSnapshot(t, source, owner, key)
	expected = current
	if _, e = ExportBackupKeys(t.Context(), cfg, body, keys); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	return body, keys, work, expected
}

// checkOfflineCarryBackup は公開APIと隔離中の元内容照合を、正本なしで検査する。
func checkOfflineCarryBackup(t *testing.T, cfg Config, owner domain.ID, key uint64, expected store.ControlState, public ed25519.PublicKey) {
	t.Helper()
	body, keys, work, expected := captureCarryOfflineFixture(t, cfg, owner, key, expected)
	report, e := VerifyBackupReplay(t.Context(), body, keys, work)
	if e != nil || !report.Replayed || report.RestoreReady {
		t.Fatal("carry replay", report, e)
	}
	checked := false
	report, e = verifyBackupReplay(t.Context(), body, keys, work, time.Now, func(root string) error {
		checked = true
		return inspectReplayedCarryState(root, owner, key, expected, public)
	})
	if e != nil || !checked || !report.Replayed || report.RestoreReady {
		t.Fatal("isolated carry state", report, e)
	}
}

// inspectReplayedCarryState は複写値と署名を照合し、満了行を機能索引として復活させない。
func inspectReplayedCarryState(root string, owner domain.ID, key uint64, expected store.ControlState, public ed25519.PublicKey) error {
	source := filepath.Join(root, "expiry", owner.String(), fmt.Sprint(key))
	state, err := inspectDeletionControl(source, owner, key)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(state, expected) {
		return fmt.Errorf("replay values differ: seq %d/%d, rows %d/%d", state.Seq, expected.Seq, len(state.Rows), len(expected.Rows))
	}
	proof, err := readBodyReclamation(state, owner, key, public)
	if err != nil || proof == nil {
		return store.ErrCorrupt
	}
	carry, err := readBodyCarry(state, *proof)
	if err != nil || carry == nil || carry.Retirement == nil || len(carry.Dedups)+len(carry.Rates) != 0 {
		return store.ErrCorrupt
	}
	return nil
}

// assertCarryOnlineBackup は元正本の現在値/世代と固定captureの一致を照合する。
func assertCarryOnlineBackup(t *testing.T, r *Repository, owner domain.ID, key uint64, expected store.ControlState, snapshot bool) {
	t.Helper()
	output := onlineOutput(t, "carry")
	capture, e := r.CopyBoardBackup(t.Context(), owner, output, OnlineBackupGroupOptions{})
	if e != nil {
		t.Fatal("online carry copy", e)
	}
	copied := filepath.Join(output, "deletion", owner.String(), fmt.Sprint(key))
	state, e := inspectDeletionControl(copied, owner, key)
	if e != nil || !reflect.DeepEqual(state, expected) {
		t.Fatal("copied state differs", e)
	}
	found := false
	for _, c := range capture.Captures {
		if c.Kind == "deletion" && c.Subkey == fmt.Sprint(key) {
			found = true
		}
	}
	if !found {
		t.Fatal("missing source capture")
	}
	m, e := store.InspectControlManifest(copied)
	if e != nil || (m.Snapshot != nil) != snapshot {
		t.Fatal("copied generation", m, e)
	}
}

// assertCarrySiteBackup は監査引渡し後、元snapshotを含む全サイトコピーの製品照合を実行する。
func assertCarrySiteBackup(t *testing.T, r *Repository, owner domain.ID, key uint64) {
	t.Helper()
	if e := r.TransferThreadAudits(t.Context(), 8); e != nil {
		t.Fatal(e)
	}
	syncOnlineAudit(t, r)
	output := onlineOutput(t, "carry-site")
	result, e := r.AssembleOnlineBackup(t.Context(), output, OnlineBackupSiteOptions{})
	if e != nil || result.RestoreReady {
		t.Fatal("snapshot site assembly", result, e)
	}
	copied := filepath.Join(output, "deletion", owner.String(), fmt.Sprint(key))
	state, e := inspectDeletionControl(copied, owner, key)
	if e != nil || !reflect.DeepEqual(state, r.posting[owner].deletions[key].State()) {
		t.Fatal("site source values", e)
	}
}
