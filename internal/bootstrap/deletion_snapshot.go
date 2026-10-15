// 削除正本の現在値をsnapshotとして検査し、WALの状態遷移検査とは分離する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const bodyCarrySnapshotReader = 60

// snapshotDeletionValue は現在値の型/状態を検査する。WALの初回intent制約は維持する。
func snapshotDeletionValue(collection, key string, old, next json.RawMessage) error {
	if len(old) != 0 {
		return store.ErrCorrupt
	}
	switch collection {
	case "deletion":
		return snapshotDeletionRecord(key, next)
	case "copy_task":
		return snapshotDeletionTask(key, next)
	case "thread_action":
		return snapshotThreadAction(key, next)
	default:
		return validateDeletion(collection, key, nil, next)
	}
}

// snapshotDeletionRecord は有効な直前状態との照合で現在の削除phaseを検査する。
func snapshotDeletionRecord(key string, next json.RawMessage) error {
	var v DeletionRecord
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if v.Phase == "intent" {
		return validateDeletion("deletion", key, nil, next)
	}
	prior := v
	if v.Audit == "complete" {
		prior.Audit = "pending"
	} else {
		prior.Phase = map[string]string{"public_stopped": "intent", "applied": "public_stopped", "cleaning": "applied"}[v.Phase]
	}
	raw, e := json.Marshal(prior)
	if e != nil {
		return e
	}
	return validateDeletion("deletion", key, raw, next)
}

// snapshotDeletionTask は完了/失敗の付帯値も既存の遷移検証器で検査する。
func snapshotDeletionTask(key string, next json.RawMessage) error {
	var v DeletionCopyTask
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if v.State == "pending" {
		return validateDeletionCopyTask(key, nil, next)
	}
	prior := v
	prior.State, prior.Verified, prior.LastError = "running", nil, nil
	if v.State == "running" {
		prior.State = "pending"
	}
	raw, e := json.Marshal(prior)
	if e != nil {
		return e
	}
	return validateDeletionCopyTask(key, raw, next)
}

// snapshotThreadAction は現在phaseでも元frame/hash/認可scopeの検査を維持する。
func snapshotThreadAction(key string, next json.RawMessage) error {
	var v ThreadActionRecord
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if v.Phase == "intent" {
		return validateThreadAction(key, nil, next)
	}
	prior := v
	prior.Phase = "intent"
	raw, e := json.Marshal(prior)
	if e != nil {
		return e
	}
	return validateThreadAction(key, raw, next)
}

// inspectDeletionLayout は初回snapshotとその旧WALだけを認め、未知の世代/候補を拒否する。
func inspectDeletionLayout(dir string, owner domain.ID, key uint64) (store.ControlManifest, error) {
	m, e := store.InspectControlManifest(dir)
	if e != nil {
		return m, e
	}
	if m.Kind != 3 || m.Owner != owner || uint64(m.Subkey) != key {
		return m, store.ErrCorrupt
	}
	names := []string{"control.current", "control-000001.wal"}
	if m.Snapshot != nil {
		if m.Generation != 2 {
			return m, store.ErrCorrupt
		}
		names = []string{"control.current", m.Snapshot.File, m.Delta.File}
		if _, e := os.Lstat(filepath.Join(dir, "control-000001.wal")); e == nil {
			names = append(names, "control-000001.wal")
		} else if !os.IsNotExist(e) {
			return m, e
		}
	}
	candidates, e := carrySnapshotCandidates(dir, m.Snapshot != nil)
	if e != nil {
		return m, e
	}
	names = append(names, candidates...)
	return m, requirePrivateDeletionFiles(dir, names)
}

// requirePrivateDeletionFiles は保持旧WALを含め、全fileの所有・権限・リンクを検査する。
func requirePrivateDeletionFiles(dir string, names []string) error {
	if e := requireEntries(dir, names); e != nil {
		return e
	}
	for _, name := range names {
		if e := privatePath(filepath.Join(dir, name), false); e != nil {
			return e
		}
	}
	return nil
}

// inspectDeletionControl はsnapshot現在値とWAL遷移をそれぞれ検査する。
func inspectDeletionControl(dir string, owner domain.ID, key uint64) (store.ControlState, error) {
	return store.InspectControlWithValidators(dir, 3, owner, key, validateDeletion, snapshotDeletionValue)
}

// checkDeletionSnapshotScope は署名済み満了元の空索引だけをsnapshot運用へ許可する。
func checkDeletionSnapshotScope(reader uint32, m store.ControlManifest, state store.ControlState) error {
	if m.Snapshot == nil {
		return nil
	}
	return checkCarrySnapshotState(reader, state)
}

// checkCarrySnapshotState は完成snapshotと未確定候補で同じ署名先行条件を要求する。
func checkCarrySnapshotState(reader uint32, state store.ControlState) error {
	if reader < bodyCarrySnapshotReader || carryRowsInState(state) != 0 || len(state.Rows["reclamation:carry_retirement"].Value) == 0 || len(state.Rows["reclamation:body"].Value) == 0 {
		return fmt.Errorf("carry snapshot requires completed erasure and reader60: %w", store.ErrCorrupt)
	}
	return nil
}

func carryRowsInState(state store.ControlState) int {
	n := 0
	for name := range state.Rows {
		collection, _, _ := strings.Cut(name, ":")
		if collection == "dedup_carry" || collection == "rate_carry" {
			n++
		}
	}
	return n
}
