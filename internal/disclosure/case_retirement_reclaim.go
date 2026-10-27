// 先行署名一覧/現在元解除に一致する案件制御全世代を物理回収し、中断後も同じ一覧から再開する。
package disclosure

import (
	"context"
	"crypto/ed25519"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"time"
)

// ReclaimCaseRetirement はsiteへ先行Sync済みの署名記録に基づき、全制御世代と空のcopy領域を削除する。
// 呼出元は共通排他・現在site最低reader51・全時計床・署名検査済み現在元snapshotを保持する。
// 一致しない残存fileや未解除元は削除前に拒否する。保存/削除不確定なら所有者を停止する。
func (s *Store) ReclaimCaseRetirement(ctx context.Context, id domain.ID, event evidence.Event, reader uint32, required []app.RequiredHoldReceipt, optional []evidence.OptionalHoldReceipt, now time.Time) error {
	intent, e := s.inspectRetirementReceipt(id, event, reader, now)
	if e != nil {
		return e
	}
	candidate := retirementIntentCandidate(id, intent)
	if e = CheckCaseRetirementSources(candidate, required, optional, domain.Time(now.UnixNano())); e != nil {
		return e
	}
	files, e := s.retirementRemainder(ctx, id, intent)
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = s.closeRetiringCase(id, intent.Fingerprint); e != nil {
		s.stopped = true
		return e
	}
	if e = s.removeRetirementRemainder(ctx, id, files); e != nil {
		s.stopped = true
		return e
	}
	return nil
}

func retirementIntentCandidate(id domain.ID, intent CaseRetirementIntent) CaseRetirementCandidate {
	return CaseRetirementCandidate{Case: id, Revision: intent.Revision, Head: intent.Head, EligibleAt: intent.EligibleAt, Clock: intent.Clock, RequiredRelease: intent.RequiredRelease, HTTPRelease: intent.HTTPRelease}
}

// closeRetiringCase は削除前に制御handleを閉じ、固定IDの作成再送を停止する。
func (s *Store) closeRetiringCase(id domain.ID, fingerprint domain.Hash) error {
	if log := s.logs[id]; log != nil {
		if e := log.Close(); e != nil {
			return e
		}
		delete(s.logs, id)
		delete(s.requests, id)
	}
	if s.retired == nil {
		s.retired = map[domain.Hash]struct{}{}
	}
	s.retired[fingerprint] = struct{}{}
	return nil
}

// removeRetirementRemainder は削除ごとに親をSyncし、成功済みfileを同じ記録から飛ばせるようにする。
func (s *Store) removeRetirementRemainder(ctx context.Context, id domain.ID, files []CaseRetirementFile) error {
	path := filepath.Join(s.root, id.String())
	for _, file := range files {
		if e := removeRetirementFile(ctx, path, id, file); e != nil {
			return e
		}
		if e := s.after("retirement:file"); e != nil {
			return e
		}
	}
	return s.removeRetirementDirectories(ctx, path)
}

// removeRetirementFile は先行削除のSync後にも対象の所有権と署名一覧との一致を再確認する。
func removeRetirementFile(ctx context.Context, path string, id domain.ID, expected CaseRetirementFile) error {
	actual, e := inspectRetirementControlFile(ctx, filepath.Join(path, "control"), filepath.Base(expected.Name), id)
	if e != nil {
		return e
	}
	if actual != expected {
		return store.ErrCorrupt
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	name := filepath.Join(path, filepath.FromSlash(expected.Name))
	if e = os.Remove(name); e != nil {
		return e
	}
	return syncDir(filepath.Dir(name))
}

func (s *Store) removeRetirementDirectories(ctx context.Context, path string) error {
	for _, name := range []string{"control", "items", "exports", "http"} {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := os.Remove(filepath.Join(path, name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	if e := s.removeRetirementCaseDirectory(path); e != nil {
		return e
	}
	if e := syncDir(s.root); e != nil {
		return e
	}
	return s.after("retirement:complete")
}

func (s *Store) removeRetirementCaseDirectory(path string) error {
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if e := syncDir(path); e != nil {
		return e
	}
	if e := s.after("retirement:directories"); e != nil {
		return e
	}
	return os.Remove(path)
}

// ResumeCaseRetirement は通常Controlを開けない部分削除を、先行登録済み署名/現在元から再開する。
// 呼出元がsite登録の耐久性・排他・全時計床/現在元署名を先に検査する。鍵や登録を補完しない。
func ResumeCaseRetirement(ctx context.Context, root string, key ed25519.PrivateKey, id domain.ID, event evidence.Event, reader uint32, required []app.RequiredHoldReceipt, optional []evidence.OptionalHoldReceipt, now time.Time) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrInvalid
	}
	s := &Store{root: root, key: key}
	return s.ReclaimCaseRetirement(ctx, id, event, reader, required, optional, now)
}
