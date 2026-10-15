// 回収対象の旧制御WALを認証済み境界・snapshot状態へ読み取り専用で照合する。
package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"reflect"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// inspectRetiredControl は確定時の全frame chain・監査要約chain・現在値を独立に再計算する。
// 不完全末尾や余分なframeを修復・切捨てせず、回収を拒否する。
func inspectRetiredControl(ctx context.Context, dir string, a candidateOwner, budget *store.HistoryBudget) (domain.U64, error) {
	if budget == nil || budget.Bytes < 64 {
		return 0, store.ErrHistoryBudget
	}
	raw, err := readPrivate(filepath.Join(dir, "control-000001.wal"), budget.Bytes)
	if err != nil {
		return 0, err
	}
	budget.Bytes -= int64(len(raw))
	if len(raw) < 64 {
		return 0, store.ErrCorrupt
	}
	h, err := store.DecodeHeader(raw[:64])
	if err != nil {
		return 0, err
	}
	expected := a.header()
	expected.Generation = 1
	expected.BaseSeq = 0
	if h != expected {
		return 0, store.ErrCorrupt
	}
	reader := bytes.NewReader(raw[64:])
	state := store.ControlState{}
	p := a.Proof
	p.Sequence = 0
	p.SourceHash = domain.Hash{}
	p.Entries = 0
	p.SummaryHash = domain.Hash{}
	validate := store.ValueValidator(validateSiteValue)
	if a.Kind == "board" {
		validate = validateBoardValue
	}
	for reader.Len() > 0 {
		if err = ctx.Err(); err != nil {
			return 0, err
		}
		if budget.Frames == 0 {
			return 0, store.ErrHistoryBudget
		}
		budget.Frames--
		frame, _, err := store.ReadFrame(reader)
		if err != nil {
			return 0, err
		}
		if len(frame.Records) != 1 {
			return 0, store.ErrCorrupt
		}
		state, err = store.ApplyControl(state, h.Kind, frame, validate)
		if err != nil {
			return 0, err
		}
		rec := frame.Records[0]
		var op store.ControlOperation
		if err = strictjson.Decode(rec.JSON, &op); err != nil {
			return 0, err
		}
		var imported *AuditEntry
		if entry, ok := auditSummary(a.Owner, a.Kind, rec, op); ok && op.Committed >= p.Since {
			imported = &entry
		}
		if err = p.advance(rec, op, imported); err != nil {
			return 0, err
		}
	}
	if p != a.Proof {
		return 0, store.ErrCorrupt
	}
	snapshot, err := readPrivate(filepath.Join(dir, fmt.Sprintf("control-%06d.snap", a.Generation)), int64(a.Length))
	if err != nil {
		return 0, err
	}
	restored, err := store.DecodeControlSnapshot(snapshot, a.header(), snapshotValues(a.Kind))
	if err != nil {
		return 0, err
	}
	if !reflect.DeepEqual(state, restored) {
		return 0, store.ErrCorrupt
	}
	return domain.U64(len(raw)), nil
}
