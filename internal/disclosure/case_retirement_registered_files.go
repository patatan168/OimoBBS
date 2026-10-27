// 起動前に登録済み回収一覧と案件正本を照合し、変更世代や古い案件への巻戻りを非変更で拒否する。
package disclosure

import (
	"context"
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// InspectCompletedCaseRetirement は登録署名/時計/残存集合を検査し、案件directoryの回収完了だけを許す。
// 呼出元は現在site登録と元解除を別途照合する。読取りで候補補完や親Syncを行わない。
func InspectCompletedCaseRetirement(ctx context.Context, root string, key ed25519.PrivateKey, id domain.ID, event evidence.Event, reader uint32, now time.Time) error {
	if err := InspectCaseRetirementRemainder(ctx, root, key, id, event, reader, now); err != nil {
		return err
	}
	_, err := os.Lstat(filepath.Join(root, id.String()))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return store.ErrIncomplete
}

// InspectCaseRetirementRemainder は署名/reader/時計と残存一覧を読取りだけで検査する。
// 呼出元が先行site登録と現在元を別途照合する。部分削除を通常Controlの復旧へ渡さない。
func InspectCaseRetirementRemainder(ctx context.Context, root string, key ed25519.PrivateKey, id domain.ID, event evidence.Event, reader uint32, now time.Time) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrInvalid
	}
	s := &Store{root: root, key: key}
	intent, e := s.inspectRetirementReceipt(id, event, reader, now)
	if e != nil {
		return e
	}
	_, e = s.retirementRemainder(ctx, id, intent)
	return e
}

// InspectRegisteredCaseRetirementFiles は読取り専用所有者で現在の全署名/固定一覧を照合する。
// 呼出元はsite登録の署名/最低reader/現在時計を先に検査する。部分削除の復旧は別経路を必要とする。
func InspectRegisteredCaseRetirementFiles(ctx context.Context, root string, key ed25519.PrivateKey, id domain.ID, intent CaseRetirementIntent, now time.Time) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrInvalid
	}
	s := &Store{root: root, key: key}
	if intent.Fingerprint != s.CaseRetirementFingerprint(id) {
		return store.ErrCorrupt
	}
	candidate := CaseRetirementCandidate{Case: id, Revision: intent.Revision, Head: intent.Head, EligibleAt: intent.EligibleAt, Clock: intent.Clock, RequiredRelease: intent.RequiredRelease, HTTPRelease: intent.HTTPRelease}
	files, e := s.InspectCaseRetirementFiles(ctx, candidate, now)
	if e != nil {
		return e
	}
	if !slices.Equal(files, intent.Files) {
		return store.ErrCorrupt
	}
	return nil
}
