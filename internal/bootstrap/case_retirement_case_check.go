// 既知案件の作成補完や原本復旧より前に、登録済み案件の最新署名と物理保存世代を照合する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"time"
)

// inspectRegisteredCaseRetirementFiles は現在存在する案件と先行登録を非変更で照合する。
// 全体の未知directory/未作成intentの検査は通常の案件検査へ残す。
func inspectRegisteredCaseRetirementFiles(root string, state store.ControlState) error {
	var site siteState
	if e := strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil {
		return e
	}
	rows, e := caseRetirementRegistrations(state, site)
	if e != nil || len(rows) == 0 {
		return e
	}
	seed, e := readPrivate(filepath.Join(root, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	entries, e := os.ReadDir(filepath.Join(root, "cases"))
	if e != nil {
		return e
	}
	return checkRegisteredCaseRetirementEntries(root, key, rows, entries)
}

func checkRegisteredCaseRetirementEntries(root string, key ed25519.PrivateKey, rows map[domain.Hash]caseRetirementRegistration, entries []os.DirEntry) error {
	for _, entry := range entries {
		var id domain.ID
		if json.Unmarshal([]byte(`"`+entry.Name()+`"`), &id) != nil {
			continue
		}
		fingerprint, e := disclosure.CaseRetirementFingerprint(key, id)
		if e != nil {
			return e
		}
		row, ok := rows[fingerprint]
		if !ok {
			continue
		}
		intent, e := disclosure.VerifyCaseRetirementIntent(row.Event, fingerprint, key.Public().(ed25519.PublicKey))
		if e != nil {
			return e
		}
		if !entry.IsDir() {
			return store.ErrCorrupt
		}
		if e = disclosure.InspectRegisteredCaseRetirementFiles(context.Background(), filepath.Join(root, "cases"), key, id, intent, time.Now()); e != nil {
			return e
		}
	}
	return nil
}
