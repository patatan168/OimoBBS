// 回収途中の残存fileを、先行登録した署名一覧の完全一致する部分集合として非変更検査する。
package disclosure

import (
	"context"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// retirementRemainder は回収済みfileの不在を許し、残存bytes/未知file/コピー残存を検査する。
// 呼出元は登録済み署名・時計/現在元解除を先に照合する。全fileを検査するまで削除しない。
func (s *Store) retirementRemainder(ctx context.Context, id domain.ID, intent CaseRetirementIntent) ([]CaseRetirementFile, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := privateRetirementDirectory(s.root); e != nil {
		return nil, e
	}
	path := filepath.Join(s.root, id.String())
	if e := privateRetirementDirectory(path); os.IsNotExist(e) {
		return []CaseRetirementFile{}, nil
	} else if e != nil {
		return nil, e
	}
	if e := checkRetirementRemainderDirectories(path); e != nil {
		return nil, e
	}
	names, e := retirementRemainderNames(filepath.Join(path, "control"))
	if e != nil {
		return nil, e
	}
	return matchRetirementRemainder(ctx, filepath.Join(path, "control"), id, intent.Files, names)
}

func privateRetirementDirectory(path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	return nil
}

func checkRetirementRemainderDirectories(path string) error {
	dir, e := os.Open(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	names, e := dir.Readdirnames(5)
	if e != nil && e != io.EOF {
		return e
	}
	if len(names) > 4 {
		return store.ErrCorrupt
	}
	for _, name := range names {
		if e := checkRetirementRemainderDirectory(path, name); e != nil {
			return e
		}
	}
	return nil
}

func checkRetirementRemainderDirectory(path, name string) error {
	if name != "control" && name != "items" && name != "exports" && name != "http" {
		return store.ErrCorrupt
	}
	dir := filepath.Join(path, name)
	if e := privateRetirementDirectory(dir); e != nil {
		return e
	}
	if name == "control" {
		return nil
	}
	return emptyRetirementDirectory(dir)
}

func emptyRetirementDirectory(dir string) error {
	file, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer file.Close()
	names, e := file.Readdirnames(1)
	if e != nil && e != io.EOF {
		return e
	}
	if len(names) != 0 {
		return store.ErrIncomplete
	}
	return nil
}

func retirementRemainderNames(path string) ([]string, error) {
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return []string{}, nil
	} else if e != nil {
		return nil, e
	}
	dir, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	names, e := dir.Readdirnames(maxCaseRetirementFiles + 1)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(names) > maxCaseRetirementFiles {
		return nil, ErrLimit
	}
	sort.Strings(names)
	return names, nil
}

func matchRetirementRemainder(ctx context.Context, path string, id domain.ID, expected []CaseRetirementFile, names []string) ([]CaseRetirementFile, error) {
	byName := make(map[string]CaseRetirementFile, len(expected))
	for _, file := range expected {
		byName[file.Name] = file
	}
	files := make([]CaseRetirementFile, 0, len(names))
	for _, name := range names {
		want, exists := byName["control/"+name]
		if !exists {
			return nil, store.ErrCorrupt
		}
		file, e := inspectRetirementControlFile(ctx, path, name, id)
		if e != nil {
			return nil, e
		}
		if file != want {
			return nil, store.ErrCorrupt
		}
		files = append(files, file)
	}
	return files, nil
}

// inspectRetirementReceipt はsite登録済み記録を現在所有者/時計へ束縛する。
func (s *Store) inspectRetirementReceipt(id domain.ID, event evidence.Event, reader uint32, now time.Time) (CaseRetirementIntent, error) {
	if s.stopped || reader < 51 || id == (domain.ID{}) {
		return CaseRetirementIntent{}, ErrInvalid
	}
	intent, e := s.VerifyCaseRetirementIntent(event, s.CaseRetirementFingerprint(id))
	if e != nil {
		return intent, e
	}
	if domain.Time(now.UnixNano()) < intent.At {
		return intent, evidence.ErrRetirementClock
	}
	return intent, nil
}
