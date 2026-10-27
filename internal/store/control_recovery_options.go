// 同じ復旧で検証した私的状態を起動境界の検査へ渡し、再走査前提の修復を避ける。
package store

import (
	"crypto/sha256"
	"errors"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/parallel"
	"os"
	"path/filepath"
)

// ControlRecoveryOptions は所有者が排他を保持する起動時だけ使用する。
type ControlRecoveryOptions struct {
	// Inspectは全WAL検証後・Sync/修復前に呼ぶ。借用状態を変更・保持してはならない。
	// 指定時は不完全末尾を読取り専用検査と同じく拒否する。
	Inspect func(ControlState) error
	// ParallelNewValuesはkind8の独立新規行だけをCPUで検証する。validateは並行呼出し可能とする。
	// 更新・削除・同じキーを含むblockは従来の順序検証へ戻す。
	ParallelNewValues bool
}

// OpenControlRecovery は同じfileの一回の読込・検証から起動境界を検査し、その成功後だけ同期する。
// snapshotも境界検査前には同期せず、成功後に元hashを再照合して同期する。
func OpenControlRecovery(dir string, kind uint16, owner domain.ID, subkey uint64, validate ValueValidator, options ControlRecoveryOptions) (*ControlLog, error) {
	return openControlRecovery(dir, kind, owner, subkey, validate, validate, true, options)
}

// InspectControlRecovery は独立行の検証だけを並行化できる読取り専用検査。同期・修復を行わない。
// ParallelNewValuesを使う場合、validateは並行呼出し可能とする。Inspect callbackは使用しない。
func InspectControlRecovery(dir string, kind uint16, owner domain.ID, subkey uint64, validate ValueValidator, parallelNewValues bool) (ControlState, error) {
	log, err := openControlRecovery(dir, kind, owner, subkey, validate, validate, false, ControlRecoveryOptions{ParallelNewValues: parallelNewValues})
	if err != nil {
		return ControlState{}, err
	}
	state := log.State()
	if err = log.Close(); err != nil {
		return ControlState{}, err
	}
	return state, nil
}

// applyIndependentReplay は一blockだけを保持し、全独立検証の終了後に連番/CASを順に適用する。
func applyIndependentReplay(old ControlState, kind uint16, frames []Frame, validate ValueValidator) (ControlState, error) {
	decoded := make([]preparedControlOperation, len(frames))
	parallel.CPU(len(frames), func(i int) {
		op, err := decodeControlOperation(frames[i])
		if err == nil && (len(op.Mutations) < 1 || len(op.Mutations) > 256) {
			err = ErrCorrupt
		}
		decoded[i] = preparedControlOperation{frames[i].FirstSeq, op, err}
	})
	for _, entry := range decoded {
		if entry.err != nil {
			return old, entry.err
		}
	}
	c := &ControlLog{header: Header{Kind: kind}, state: old, validator: validate}
	independent := c.checkIndependentValues(decoded) == nil
	if independent {
		if err := c.validateIndependentValues(decoded); err != nil {
			return old, err
		}
	}
	// oldは復旧だけが所有する未公開map。全候補の適用が済むまで実fileと公開状態は変更しない。
	next := old
	for _, entry := range decoded {
		op := entry.op
		candidate, err := applyControlOperationPrepared(controlReplaySubset(next, op.Mutations), kind, entry.firstSeq, op, validate, false, independent)
		if err != nil {
			return old, err
		}
		next = mergeControlReplay(next, candidate, op.Mutations)
	}
	return next, nil
}

// syncInspectedControlSnapshot は境界検査後、同じ必須長・hashのsnapshotだけを同期する。
func syncInspectedControlSnapshot(dir string, m ControlManifest) (err error) {
	path := filepath.Join(dir, m.Snapshot.File)
	if err := privateRegular(path, false); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, int64(m.Snapshot.Length)+1))
	if err != nil {
		return err
	}
	var actual domain.Hash
	copy(actual[:], hash.Sum(nil))
	if n != int64(m.Snapshot.Length) || actual != m.Snapshot.SHA {
		return ErrCorrupt
	}
	return f.Sync()
}
