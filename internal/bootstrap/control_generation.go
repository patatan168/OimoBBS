// currentを基準に保存世代を列挙し、現行snapshotと認証済み境界を結び付ける。
package bootstrap

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

type controlGeneration struct {
	Manifest store.ControlManifest
	Anchor   *controlAnchor
	State    store.ControlState
	Retained []string
	Pending  []string
}

// inspectControlGeneration は現行世代を完全検査し、旧fileと中断候補を区別する。
// Pendingを返した場合の再開・回収判断は呼出元の責務。稼働起動へはまだ接続しない。
func inspectControlGeneration(dir, kind string, owner, site domain.ID, key domain.Hash) (controlGeneration, error) {
	var result controlGeneration
	if site == (domain.ID{}) || owner == (domain.ID{}) || (kind == "site" && site != owner) || (kind == "board" && site == owner) || (kind != "site" && kind != "board") {
		return result, store.ErrCorrupt
	}
	if err := privatePath(dir, true); err != nil {
		return result, err
	}
	m, err := store.InspectControlManifest(dir)
	if err != nil {
		return result, err
	}
	wanted := uint16(1)
	if kind == "board" {
		wanted = 2
	}
	if m.Kind != wanted || m.Owner != owner || m.Subkey != 0 {
		return result, store.ErrCorrupt
	}
	active := map[string]bool{"control.current": true, m.Delta.File: true}
	if m.Snapshot != nil {
		name := fmt.Sprintf("control-%06d.anchor.json", m.Generation)
		a, err := readControlAnchor(filepath.Join(dir, name), site, domain.ID{}, key)
		if err != nil {
			return result, err
		}
		item := a.Owner
		if item.Owner != owner || item.Kind != kind || item.Generation != m.Generation || item.Sequence != m.Snapshot.Seq || item.Length != m.Snapshot.Length || item.SHA != m.Snapshot.SHA {
			return result, store.ErrCorrupt
		}
		result.Anchor = &a
		active[name] = true
		active[m.Snapshot.File] = true
	} else if m.Generation != 1 {
		return result, store.ErrCorrupt
	}
	f, err := os.Open(dir)
	if err != nil {
		return result, err
	}
	names, readErr := f.Readdirnames(257)
	closeErr := f.Close()
	if readErr != nil && readErr != io.EOF {
		return result, readErr
	}
	if closeErr != nil {
		return result, closeErr
	}
	if len(names) > 256 {
		return result, store.ErrHistoryBudget
	}
	for _, name := range names {
		if err = privatePath(filepath.Join(dir, name), false); err != nil {
			return result, err
		}
		if active[name] {
			continue
		}
		if strings.HasPrefix(name, ".install-") {
			suffix := strings.TrimPrefix(name, ".install-")
			if suffix == "" || strings.Trim(suffix, "0123456789") != "" {
				return result, store.ErrCorrupt
			}
			result.Pending = append(result.Pending, name)
			continue
		}
		generation, ok := controlFileGeneration(name)
		if !ok {
			return result, store.ErrCorrupt
		}
		switch {
		case generation < uint64(m.Generation):
			result.Retained = append(result.Retained, name)
		case uint64(m.Generation) != ^uint64(0) && generation == uint64(m.Generation)+1:
			result.Pending = append(result.Pending, name)
		default:
			return result, store.ErrCorrupt
		}
	}
	apply := store.ValueValidator(validateSiteValue)
	if kind == "board" {
		apply = validateBoardValue
	}
	result.State, err = store.InspectControlWithValidators(dir, wanted, owner, 0, apply, snapshotValues(kind))
	if err != nil {
		return controlGeneration{}, err
	}
	// snapshotの行数はdelta適用後の行数とは別なので、その比較は候補生成時に行う。
	result.Manifest = m
	sort.Strings(result.Retained)
	sort.Strings(result.Pending)
	return result, nil
}

func controlFileGeneration(name string) (uint64, bool) {
	for _, suffix := range []string{".wal", ".snap", ".anchor.json"} {
		if !strings.HasPrefix(name, "control-") || !strings.HasSuffix(name, suffix) {
			continue
		}
		text := strings.TrimSuffix(strings.TrimPrefix(name, "control-"), suffix)
		generation, err := strconv.ParseUint(text, 10, 64)
		if err != nil || generation == 0 || name != fmt.Sprintf("control-%06d%s", generation, suffix) || (generation == 1 && suffix != ".wal") {
			return 0, false
		}
		return generation, true
	}
	return 0, false
}
