// 案件/必須元の全署名集合を原本Journal復旧前に照合し、有効台帳の欠落を補完しない。
package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"io"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"time"
)

// inspectRequiredHoldStorage は先行有効化intent/全案件/全元を非変更で検査する。
// allowPending時は既知案件作成だけを先に再開し、元作成は板所有者へ残す。
func inspectRequiredHoldStorage(cfg Config, site siteState, state store.ControlState, allowPending bool) error {
	if _, e := os.Lstat(filepath.Join(cfg.DataDir, "reports", backupRequiredOmissionName)); e == nil {
		return errors.New("excluded required-original hold history requires independent restoration")
	} else if !os.IsNotExist(e) {
		return e
	}
	activations, e := requiredHoldActivations(state, site)
	if e != nil {
		return e
	}
	if e = inspectRequiredHoldParent(cfg.DataDir, activations, allowPending); e != nil {
		return e
	}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	cases, e := requiredCaseSnapshots(cfg.DataDir, key, site.MinimumReader, allowPending)
	if e != nil {
		return e
	}
	sources, e := inspectRequiredSourcesWithRetirements(cfg.DataDir, activations, key, allowPending, site.MinimumReader, state, cases)
	if e != nil {
		return e
	}
	if e = disclosure.CheckRequiredCaseReservationsWithRenewals(cases, sources.Receipts, sources.Renewals); e != nil {
		return e
	}
	if e = inspectRequiredHeldOriginalsWithCases(cfg.DataDir, key, sources.Receipts, cases, domain.Time(time.Now().UnixNano())); e != nil {
		return e
	}
	return disclosure.InspectRequiredCompletedCopies(filepath.Join(cfg.DataDir, "cases"), key, cases, time.Now())
}

// inspectRequiredSourcesWithRetirements は全元の署名境界を確認してから回収済み解除を照合する。
func inspectRequiredSourcesWithRetirements(root string, activations map[domain.ID]requiredHoldActivation, key ed25519.PrivateKey, allowPending bool, reader uint32, state store.ControlState, cases []disclosure.RequiredCaseInspection) (requiredHoldSourceSnapshots, error) {
	sources, e := inspectRequiredHoldSources(root, activations, key, allowPending, reader)
	if e != nil {
		return sources, e
	}
	return requiredSourcesWithRetirements(state, key, cases, sources, domain.Time(time.Now().UnixNano()))
}

// requiredCaseSnapshots は最初に非変更検査し、許可された既知作成途中だけを案件所有者で再開する。
func requiredCaseSnapshots(root string, key ed25519.PrivateKey, reader uint32, allowPending bool) ([]disclosure.RequiredCaseInspection, error) {
	path := filepath.Join(root, "cases")
	cases, e := disclosure.InspectRequiredCaseMetadataVersion(path, key, reader)
	if !allowPending || !errors.Is(e, store.ErrIncomplete) {
		return cases, e
	}
	s, e := disclosure.Open(path, key)
	if e != nil {
		return nil, e
	}
	if e = s.Close(); e != nil {
		return nil, e
	}
	return disclosure.InspectRequiredCaseMetadataVersion(path, key, reader)
}

// requiredHoldSourceSnapshots は元の現在参照と最新延長証明を同じ読取り走査から保持する。
type requiredHoldSourceSnapshots struct {
	Receipts []app.RequiredHoldReceipt
	Renewals []app.RequiredHoldRenewalReceipt
}

// inspectRequiredHoldSources は全板の元署名/reader/時計床と延長証明を非変更で検査する。
func inspectRequiredHoldSources(root string, activations map[domain.ID]requiredHoldActivation, key ed25519.PrivateKey, allowPending bool, reader uint32) (requiredHoldSourceSnapshots, error) {
	result := requiredHoldSourceSnapshots{}
	now := domain.Time(time.Now().UnixNano())
	for board, a := range activations {
		inspection, e := inspectRequiredHoldSource(root, board, a, key, allowPending, reader, now)
		if e != nil {
			return requiredHoldSourceSnapshots{}, e
		}
		result.Receipts = append(result.Receipts, inspection.Receipts...)
		result.Renewals = append(result.Renewals, inspection.Renewals...)
	}
	return result, nil
}

// inspectRequiredHoldSource は準備中の既知空初期化だけを後続所有者へ渡す。
func inspectRequiredHoldSource(root string, board domain.ID, a requiredHoldActivation, key ed25519.PrivateKey, allowPending bool, reader uint32, now domain.Time) (app.RequiredHoldsInspection, error) {
	inspection, e := app.InspectRequiredOriginalHolds(requiredHoldStoragePath(root, board), board, 10, key)
	if a.Phase == "preparing" {
		if !allowPending {
			return inspection, store.ErrIncomplete
		}
		if os.IsNotExist(e) || errors.Is(e, store.ErrIncomplete) {
			return app.RequiredHoldsInspection{}, nil
		}
		if e == nil && len(inspection.Receipts) != 0 {
			return inspection, store.ErrCorrupt
		}
	}
	if e != nil {
		return inspection, e
	}
	return inspection, checkRequiredHoldSourceBoundary(inspection, reader, now)
}

// checkRequiredHoldSourceBoundary は新履歴を古いreaderへ渡さず、時計逆行を拒否する。
func checkRequiredHoldSourceBoundary(i app.RequiredHoldsInspection, reader uint32, now domain.Time) error {
	if i.MinimumReader > reader {
		return errors.New("required-original renewal requires reader47")
	}
	if now < i.Floor {
		return evidence.ErrRetirementClock
	}
	return nil
}

// inspectRequiredHoldParent は128板の既知台帳/準備中候補だけを有界検査する。
func inspectRequiredHoldParent(root string, activations map[domain.ID]requiredHoldActivation, allowPending bool) error {
	path := filepath.Join(root, "reports", requiredHoldStorageDirectory)
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return requiredHoldParentMissing(activations, allowPending)
	}
	if e != nil {
		return e
	}
	if len(activations) == 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	entries, e := readRequiredHoldParent(path)
	if e != nil {
		return e
	}
	allowed := requiredHoldParentNames(activations)
	for _, entry := range entries {
		directory, known := allowed[entry.Name()]
		if !known {
			return store.ErrCorrupt
		}
		if e = privatePath(filepath.Join(path, entry.Name()), directory); e != nil {
			return e
		}
	}
	return nil
}

// requiredHoldParentMissing は準備中の不在だけを許し、有効化済みの空集合台帳も欠落扱いにする。
func requiredHoldParentMissing(activations map[domain.ID]requiredHoldActivation, allowPending bool) error {
	for _, a := range activations {
		if a.Phase == "active" {
			return store.ErrCorrupt
		}
		if !allowPending {
			return store.ErrIncomplete
		}
	}
	return nil
}

// requiredHoldParentNames は板別intentが準備中の場合だけ固定候補名を許可集合へ加える。
func requiredHoldParentNames(activations map[domain.ID]requiredHoldActivation) map[string]bool {
	result := map[string]bool{}
	for board, a := range activations {
		result[board.String()] = true
		if a.Phase == "preparing" {
			name := "." + board.String() + ".create.frame"
			result[name] = false
			result[name+".tmp"] = false
		}
	}
	return result
}

// readRequiredHoldParent は既知板数の三倍を上限に読み、過剰なentryやClose失敗を拒否する。
func readRequiredHoldParent(path string) ([]os.DirEntry, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	entries, readErr := f.ReadDir(maxPersistentBoards*3 + 1)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > maxPersistentBoards*3 {
		return nil, store.ErrCorrupt
	}
	return entries, nil
}
