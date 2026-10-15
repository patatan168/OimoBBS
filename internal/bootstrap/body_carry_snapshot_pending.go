// 未確定snapshotの既知prefixだけを照合し、既存ResumeSnapshotで段階再開する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

type carrySnapshotPlan struct {
	snapshot, delta, current []byte
}

// carrySnapshotCandidates は初回世代候補とcurrent設置用の私有一時fileだけを列挙する。
func carrySnapshotCandidates(dir string, completed bool) ([]string, error) {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	if len(entries) > 8 {
		return nil, store.ErrCorrupt
	}
	names := []string{}
	for _, v := range entries {
		name := v.Name()
		if strings.HasPrefix(name, ".install-") || !completed && (name == "control-000002.snap" || name == "control-000002.wal") {
			names = append(names, name)
		}
	}
	return names, nil
}

// prepareCarrySnapshotPlan は同じ現在値から同じsnapshot/header/currentを再生成する。
func prepareCarrySnapshotPlan(dir string, m store.ControlManifest, state store.ControlState) (carrySnapshotPlan, error) {
	var plan carrySnapshotPlan
	h := store.Header{Kind: 3, Owner: m.Owner, Key: uint64(m.Subkey), Generation: 2, BaseSeq: uint64(state.Seq)}
	var e error
	if m.Snapshot == nil {
		plan.snapshot, e = store.EncodeControlSnapshot(h, state, 6, snapshotDeletionValue)
	} else {
		h.BaseSeq = uint64(m.Snapshot.Seq)
		plan.snapshot, e = readPrivate(filepath.Join(dir, m.Snapshot.File), 64<<20)
	}
	if e != nil {
		return plan, e
	}
	plan.delta, e = store.EncodeHeader(h)
	if e != nil {
		return plan, e
	}
	next := store.ControlManifest{Schema: 1, Kind: 3, Owner: m.Owner, Subkey: m.Subkey, Generation: 2,
		Snapshot: &store.ControlSnapshot{File: "control-000002.snap", Length: domain.U64(len(plan.snapshot)), SHA: sha256.Sum256(plan.snapshot), Seq: domain.U64(h.BaseSeq)},
		Delta:    store.Delta{File: "control-000002.wal", BaseSeq: domain.U64(h.BaseSeq), RequiredSeq: domain.U64(h.BaseSeq), RequiredEnd: 64, RequiredSHA: sha256.Sum256(plan.delta)}}
	plan.current, e = store.EncodeControlCurrent(next)
	return plan, e
}

// inspectPendingCarrySnapshot はどの修復よりも先に署名/空索引/本体消去/prefixを検査する。
func inspectPendingCarrySnapshot(cfg Config, reader uint32, dir string, m store.ControlManifest, state store.ControlState, public ed25519.PublicKey) error {
	names, e := carrySnapshotCandidates(dir, m.Snapshot != nil)
	if e != nil || len(names) == 0 {
		return e
	}
	if reader < bodyCarrySnapshotReader || carryRowsInState(state) != 0 || len(state.Rows["reclamation:carry_retirement"].Value) == 0 {
		return store.ErrCorrupt
	}
	if e = checkPendingCarryBody(cfg, m, state, public); e != nil {
		return e
	}
	if e = inspectPendingCarryHistory(dir, m, state, public); e != nil {
		return e
	}
	plan, e := prepareCarrySnapshotPlan(dir, m, state)
	if e != nil {
		return e
	}
	return inspectCarrySnapshotPrefixes(dir, names, plan)
}

// checkPendingCarryBody は元署名と公開本体の物理消去を非変更で確認する。
func checkPendingCarryBody(cfg Config, m store.ControlManifest, state store.ControlState, public ed25519.PublicKey) error {
	proof, e := readBodyReclamation(state, m.Owner, uint64(m.Subkey), public)
	if e != nil {
		return e
	}
	if proof == nil {
		return store.ErrCorrupt
	}
	path := filepath.Join(cfg.DataDir, "boards", m.Owner.String(), "threads", fmt.Sprint(m.Subkey))
	if e = store.CheckBodyReclamationComplete(context.Background(), path, proof.Files); e != nil {
		return e
	}
	return nil
}

// inspectPendingCarryHistory は段階再開前にも旧履歴の署名保存境界を検査する。
func inspectPendingCarryHistory(dir string, m store.ControlManifest, state store.ControlState, public ed25519.PublicKey) error {
	path := filepath.Join(dir, "control-000001.wal")
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	h := store.Header{Kind: 3, Owner: m.Owner, Key: uint64(m.Subkey), Generation: 2, BaseSeq: uint64(state.Seq)}
	if m.Snapshot != nil {
		var e error
		h, state, e = readCarrySnapshotBase(dir, m.Owner, uint64(m.Subkey))
		if e != nil {
			return e
		}
	}
	return inspectExpiredCarryWAL(context.Background(), path, h, state, public)
}

// inspectCarrySnapshotPrefixes は空/途中/完成prefixだけを認め、異なるbytesや過大fileを拒否する。
func inspectCarrySnapshotPrefixes(dir string, names []string, plan carrySnapshotPlan) error {
	for _, name := range names {
		want := plan.current
		if name == "control-000002.snap" {
			want = plan.snapshot
		} else if name == "control-000002.wal" {
			want = plan.delta
		}
		raw, e := readPrivate(filepath.Join(dir, name), int64(len(want)))
		if e != nil {
			return e
		}
		if !bytes.HasPrefix(want, raw) {
			return store.ErrCorrupt
		}
	}
	return nil
}

// resumePendingCarrySnapshot は照合済み一時currentを掃除し、初回世代の一致候補だけ再開する。
func (b *postingBoard) resumePendingCarrySnapshot(dir string, key uint64, log *store.ControlLog) error {
	m, e := store.InspectControlManifest(dir)
	if e != nil {
		return e
	}
	names, e := carrySnapshotCandidates(dir, m.Snapshot != nil)
	if e != nil || len(names) == 0 {
		return e
	}
	if e = inspectPendingCarrySnapshot(Config{DataDir: b.root}, readerVersion, dir, m, log.State(), b.key.Public().(ed25519.PublicKey)); e != nil {
		return e
	}
	plan, e := prepareCarrySnapshotPlan(dir, m, log.State())
	if e != nil {
		return e
	}
	if e = removeCarryInstallPrefixes(dir, names); e != nil {
		return e
	}
	if m.Snapshot != nil {
		return nil
	}
	b.deletionEpoch.Add(1)
	result := log.ResumeSnapshot(plan.snapshot)
	if result.Status != store.Durable {
		b.stopped = true
		if result.Err == nil {
			return store.ErrCorrupt
		}
		return result.Err
	}
	return b.afterDeletion("carry_snapshot:resumed")
}

// removeCarryInstallPrefixes は内容照合済み一時currentだけをunlinkして親をSyncする。
func removeCarryInstallPrefixes(dir string, names []string) error {
	for _, name := range names {
		if strings.HasPrefix(name, ".install-") {
			if e := os.Remove(filepath.Join(dir, name)); e != nil {
				return e
			}
		}
	}
	return store.SyncDirectory(dir)
}
