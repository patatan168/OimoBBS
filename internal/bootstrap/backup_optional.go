// 通常backupで除外する非必須HTTP記録を署名し、欠落を隔離再生結果へ引き継ぐ。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const backupOptionalOmissionName = "optional-http-omission.json"
const backupOptionalOmissionLimit = 4096

type backupOptionalOmission struct {
	Schema   string      `json:"schema"`
	Backup   domain.ID   `json:"backup_id"`
	Site     domain.ID   `json:"site_id"`
	Source   domain.ID   `json:"source_owner_id"`
	Sequence domain.U64  `json:"site_sequence"`
	Captured domain.Time `json:"captured_at_ns"`
	Reason   string      `json:"reason"`
}
type backupOptionalEnvelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// backupOptionalMessage は記録eventと区別する用途文字列へ署名対象を束縛する。
func backupOptionalMessage(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return append([]byte("oimo/backup-optional-http-omission/v1\x00"), h[:]...)
}

// backupOptionalEnabled は捕捉済みsiteの有効化状態を検証する。未完了intentは捕捉しない。
func backupOptionalEnabled(state store.ControlState, site domain.ID) (bool, error) {
	row, ok := state.Rows["optional_http:http"]
	if !ok {
		return false, nil
	}
	var a optionalLogActivation
	var s siteState
	if strictjson.Decode(row.Value, &a) != nil || strictjson.Decode(state.Rows["site:state"].Value, &s) != nil || a.Schema != "optional-http-activation-v1" || a.Site != site || s.ID != site || s.MinimumReader < 39 {
		return false, store.ErrCorrupt
	}
	if a.Phase != "active" {
		return false, store.ErrIncomplete
	}
	return true, nil
}

// encodeBackupOptionalOmission は個人情報を含まない除外説明だけをサイト鍵で署名する。
func encodeBackupOptionalOmission(id, site domain.ID, seq domain.U64, at domain.Time, key ed25519.PrivateKey) ([]byte, error) {
	p := backupOptionalOmission{"optional-http-backup-omission-v1", id, site, evidence.OptionalOwner(site), seq, at, "ordinary_backup_scope_excluded"}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	return json.Marshal(backupOptionalEnvelope{raw, base64.StdEncoding.EncodeToString(ed25519.Sign(key, backupOptionalMessage(raw)))})
}

// verifyBackupOptionalPayload は別backupへの転用、捕捉境界の不一致と署名改変を拒否する。
func verifyBackupOptionalPayload(raw []byte, m backupManifest, state store.ControlState, at domain.Time, public ed25519.PublicKey) error {
	var env backupOptionalEnvelope
	var p backupOptionalOmission
	if len(raw) > backupOptionalOmissionLimit || strictjson.Decode(raw, &env) != nil || strictjson.Decode(env.Payload, &p) != nil {
		return store.ErrCorrupt
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != env.Signature || !ed25519.Verify(public, backupOptionalMessage(env.Payload), sig) {
		return errors.New("backup HTTP log omission signature mismatch")
	}
	if p.Schema != "optional-http-backup-omission-v1" || p.Backup != m.ID || p.Site != m.Site || p.Source != evidence.OptionalOwner(m.Site) || p.Sequence != state.Seq || p.Captured != at || p.Reason != "ordinary_backup_scope_excluded" {
		return errors.New("backup HTTP log omission boundary mismatch")
	}
	for _, cut := range m.ControlCut {
		if cut.Kind == "site" && cut.Owner == m.Site && cut.Sequence == p.Sequence {
			return nil
		}
	}
	return store.ErrCorrupt
}

// verifyBackupOptionalOmission は認証済みファイル集合とsite状態の両方から除外の要否を確定する。
func verifyBackupOptionalOmission(ctx context.Context, root string, m backupManifest) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	var siteEntry, meta backupEntry
	for _, entry := range m.Entries {
		if entry.Kind == "site" {
			siteEntry = entry
		}
		if entry.Kind == "metadata" {
			meta = entry
		}
	}
	state, e := store.InspectControlWithValidators(filepath.Join(root, filepath.FromSlash(backupEntryPath(siteEntry))), 1, m.Site, 0, validateSiteValue, snapshotSiteValue)
	if e != nil {
		return e
	}
	enabled, e := backupOptionalEnabled(state, m.Site)
	if e != nil {
		return e
	}
	found := false
	for _, f := range meta.Files {
		if f.Name == backupOptionalOmissionName {
			found = true
		}
	}
	if enabled != found || found != backupOptionalDeclared(m) {
		return errors.New("backup HTTP log omission declaration missing or unexpected")
	}
	if !enabled {
		return nil
	}
	dir := filepath.Join(root, filepath.FromSlash(backupEntryPath(meta)))
	markerRaw, e := readPrivate(filepath.Join(dir, "instance.json"), 4096)
	if e != nil {
		return e
	}
	var marker instance
	if strictjson.Decode(markerRaw, &marker) != nil || marker.SiteID != m.Site {
		return store.ErrCorrupt
	}
	raw, e := readPrivate(filepath.Join(dir, backupOptionalOmissionName), backupOptionalOmissionLimit)
	if e != nil {
		return e
	}
	return verifyBackupOptionalPayload(raw, m, state, meta.Captured, ed25519.PublicKey(marker.SigningPublic[:]))
}

// addOptionalOmission は停止中siteの捕捉境界から署名説明を生成し、全体予算へ計上する。
func (p *backupPlan) addOptionalOmission(root string, entry *backupEntry) error {
	state, e := inspectRuntimeControl(root, "site", p.manifest.Site)
	if e != nil {
		return e
	}
	enabled, e := backupOptionalEnabled(state, p.manifest.Site)
	if e != nil || !enabled {
		return e
	}
	seed, e := readPrivate(filepath.Join(root, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	raw, e := encodeBackupOptionalOmission(p.manifest.ID, p.manifest.Site, state.Seq, entry.Captured, key)
	if e != nil {
		return e
	}
	f := backupFile{backupOptionalOmissionName, domain.U64(len(raw)), sha256.Sum256(raw)}
	if e = p.addSource(backupSource{target: backupEntryPath(*entry) + "/" + f.Name, file: f, generated: raw}); e != nil {
		return e
	}
	entry.Files = append(entry.Files, f)
	p.manifest.OptionalHTTPLogsOmitted = true
	return nil
}
