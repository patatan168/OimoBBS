// 空になった満了carry正本を初回snapshotへ切り替え、照合済み旧WALだけを回収する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// CompactExpiredBodyCarry は行削除済みの元をsnapshotへ切り替え、旧WALを物理回収する。
// 案件コピー/外部backupは対象外。未削除行や未知ファイルは保持して拒否する。
func (r *Repository) CompactExpiredBodyCarry(ctx context.Context, owner domain.ID, key uint64) error {
	if e := r.compactBodyCarry(ctx, owner, key, false); e != nil {
		return e
	}
	if _, e := r.enableStorageReader(ctx, bodyCarrySnapshotReader, "body_carry_snapshot_enable"); e != nil {
		return e
	}
	return r.compactBodyCarry(ctx, owner, key, true)
}

// compactBodyCarry はreader更新前後の元照合を行い、所有者列内だけで切替/回収する。
func (r *Repository) compactBodyCarry(ctx context.Context, owner domain.ID, key uint64, apply bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	b := r.posting[owner]
	if b == nil {
		return store.ErrIncomplete
	}
	_, e := b.worker.Submit(ctx, func() (any, error) {
		if _, e := inspectDeletionLayout(filepath.Join(b.root, "expiry", b.owner.String(), fmt.Sprint(key)), b.owner, key); e != nil {
			return nil, e
		}
		if _, e := b.prepareCarryRetirement(ctx, key); e != nil {
			return nil, e
		}
		state := b.deletions[key].State()
		if carryRowsInState(state) != 0 || len(state.Rows["reclamation:carry_retirement"].Value) == 0 {
			return nil, store.ErrIncomplete
		}
		if !apply {
			return nil, nil
		}
		return nil, b.compactCarrySource(ctx, key)
	})
	return e
}

// compactCarrySource は現在値を維持し、切替確定後に旧履歴を再照合する。
func (b *postingBoard) compactCarrySource(ctx context.Context, key uint64) error {
	dir := filepath.Join(b.root, "expiry", b.owner.String(), fmt.Sprint(key))
	if _, e := inspectDeletionLayout(dir, b.owner, key); e != nil {
		return e
	}
	if e := b.resumePendingCarrySnapshot(dir, key, b.deletions[key]); e != nil {
		return e
	}
	if e := b.switchCarrySnapshot(dir, key); e != nil {
		return e
	}
	if e := b.afterDeletion("carry_snapshot:switched"); e != nil {
		return e
	}
	return b.reclaimCarrySourceWAL(ctx, dir, key)
}

// switchCarrySnapshot は新規作成logも専用snapshot検証器へ開き直してから切り替える。
func (b *postingBoard) switchCarrySnapshot(dir string, key uint64) error {
	log := b.deletions[key]
	if _, found := log.SnapshotIdentity(); found {
		return nil
	}
	state := log.State()
	if e := log.Close(); e != nil {
		b.stopped = true
		return e
	}
	next, e := store.OpenControlWithValidators(dir, 3, b.owner, key, validateDeletion, snapshotDeletionValue)
	if e != nil {
		b.stopped = true
		return e
	}
	b.deletions[key] = next
	if !reflect.DeepEqual(next.State(), state) {
		b.stopped = true
		return store.ErrCorrupt
	}
	h := next.HistoryHeader()
	h.Generation, h.BaseSeq = h.Generation+1, uint64(state.Seq)
	raw, e := store.EncodeControlSnapshot(h, state, 6, snapshotDeletionValue)
	if e != nil {
		return e
	}
	b.deletionEpoch.Add(1)
	result := next.SwitchSnapshot(raw)
	if result.Status != store.Durable {
		b.stopped = true
		if result.Err == nil {
			return store.ErrCorrupt
		}
		return result.Err
	}
	return nil
}

// reclaimCarrySourceWAL は旧WALの全集合/署名保存境界を照合してからunlinkと親Syncを行う。
func (b *postingBoard) reclaimCarrySourceWAL(ctx context.Context, dir string, key uint64) error {
	path := filepath.Join(dir, "control-000001.wal")
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return store.SyncDirectory(dir)
	} else if e != nil {
		return e
	}
	h, base, e := readCarrySnapshotBase(dir, b.owner, key)
	if e != nil {
		return e
	}
	if e = inspectExpiredCarryWAL(ctx, path, h, base, b.key.Public().(ed25519.PublicKey)); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	if e = b.afterDeletion("carry_snapshot:old_unlinked"); e != nil {
		return e
	}
	return store.SyncDirectory(dir)
}

// readCarrySnapshotBase はcurrentが指定する完成snapshotだけを復号する。
func readCarrySnapshotBase(dir string, owner domain.ID, key uint64) (store.Header, store.ControlState, error) {
	m, e := store.InspectControlManifest(dir)
	if e != nil || m.Snapshot == nil || m.Generation != 2 {
		return store.Header{}, store.ControlState{}, store.ErrCorrupt
	}
	raw, e := readPrivate(filepath.Join(dir, m.Snapshot.File), 64<<20)
	if e != nil {
		return store.Header{}, store.ControlState{}, e
	}
	if domain.U64(len(raw)) != m.Snapshot.Length || sha256.Sum256(raw) != m.Snapshot.SHA {
		return store.Header{}, store.ControlState{}, store.ErrCorrupt
	}
	h := store.Header{Kind: 3, Owner: owner, Key: key, Generation: 2, BaseSeq: uint64(m.Snapshot.Seq)}
	base, e := store.DecodeControlSnapshot(raw, h, snapshotDeletionValue)
	if e != nil {
		return store.Header{}, store.ControlState{}, e
	}
	return h, base, nil
}

// inspectExpiredCarryWAL は読取り予算内で旧世代を再生し、snapshot現在値との一致を要求する。
func inspectExpiredCarryWAL(ctx context.Context, path string, h store.Header, base store.ControlState, public ed25519.PublicKey) error {
	f, e := openCarryWAL(path)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = inspectCarryWALHeader(f, h); e != nil {
		return e
	}
	state, e := replayExpiredCarryWAL(ctx, f, base.Seq, public)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(state, base) {
		return store.ErrCorrupt
	}
	return nil
}

// openCarryWAL は私有通常fileと読取りbyte予算を検査する。
func openCarryWAL(path string) (*os.File, error) {
	if e := privatePath(path, false); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		_ = f.Close()
		return nil, e
	}
	if info.Size() > 64<<20 {
		_ = f.Close()
		return nil, store.ErrHistoryBudget
	}
	return f, nil
}

// inspectCarryWALHeader は初回元世代と所有板/スレッドの完全一致を要求する。
func inspectCarryWALHeader(input io.Reader, h store.Header) error {
	hb := make([]byte, 64)
	if _, e := io.ReadFull(input, hb); e != nil {
		return e
	}
	old, e := store.DecodeHeader(hb)
	if e != nil || old.Kind != h.Kind || old.Owner != h.Owner || old.Key != h.Key || old.Generation != 1 || old.BaseSeq != 0 {
		return store.ErrCorrupt
	}
	return nil
}

// replayExpiredCarryWAL は署名保存境界を確認しながら旧controlを有界再生する。

func replayExpiredCarryWAL(ctx context.Context, input io.Reader, end domain.U64, public ed25519.PublicKey) (store.ControlState, error) {
	if end > 200000 {
		return store.ControlState{}, store.ErrHistoryBudget
	}
	state := store.ControlState{Rows: map[string]store.ControlRow{}}
	for uint64(state.Seq) < uint64(end) {
		if e := ctx.Err(); e != nil {
			return state, e
		}
		frames, _, e := store.ReadWALBlock(input)
		if e != nil {
			return state, e
		}
		for _, frame := range frames {
			next, e := store.ApplyControl(state, 3, frame, validateDeletion)
			if e != nil {
				return state, e
			}
			if e = checkCarryErasureBoundary(state, next, public); e != nil {
				return state, e
			}
			state = next
		}
	}
	var tail [1]byte
	if n, e := input.Read(tail[:]); n != 0 || e != io.EOF {
		return state, store.ErrCorrupt
	}
	return state, nil
}

// checkCarryErasureBoundary は過去の全集合を、削除開始の署名へ照合する。
func checkCarryErasureBoundary(before, after store.ControlState, public ed25519.PublicKey) error {
	if len(before.Rows["reclamation:carry_retirement"].Value) != 0 || len(after.Rows["reclamation:carry_retirement"].Value) == 0 {
		return nil
	}
	var proof app.BodyReclamation
	if e := strictjson.Decode(before.Rows["reclamation:body"].Value, &proof); e != nil {
		return e
	}
	carry, e := readBodyCarry(before, proof)
	if e != nil || carry == nil {
		return store.ErrCorrupt
	}
	var v app.BodyCarryRetirement
	if e = strictjson.Decode(after.Rows["reclamation:carry_retirement"].Value, &v); e != nil {
		return e
	}
	return v.VerifySource(proof, *carry, domain.Time(time.Now().UnixNano()), public)
}
