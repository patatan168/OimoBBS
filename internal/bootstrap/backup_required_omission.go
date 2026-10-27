// 通常backupから除外する必須予約履歴を署名し、隔離再生と製品復元の境界を維持する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"slices"
	"strings"
)

const backupRequiredOmissionName = "required-original-holds-omission.json"
const backupRequiredOmissionLimit = 32 << 10

type backupRequiredOmission struct {
	Schema   string      `json:"schema"`
	Backup   domain.ID   `json:"backup_id"`
	Site     domain.ID   `json:"site_id"`
	Sequence domain.U64  `json:"site_sequence"`
	Captured domain.Time `json:"captured_at_ns"`
	Boards   []domain.ID `json:"board_ids"`
	Reason   string      `json:"reason"`
}

// backupRequiredBoards は捕捉済みsiteのactive板別予約だけを順序固定して列挙する。
func backupRequiredBoards(state store.ControlState, site domain.ID) ([]domain.ID, error) {
	var s siteState
	if strictjson.Decode(state.Rows["site:state"].Value, &s) != nil || s.ID != site {
		return nil, store.ErrCorrupt
	}
	activations, e := requiredHoldActivations(state, s)
	if e != nil {
		return nil, e
	}
	boards := make([]domain.ID, 0, len(activations))
	for id, a := range activations {
		if a.Phase != "active" {
			return nil, store.ErrIncomplete
		}
		boards = append(boards, id)
	}
	slices.SortFunc(boards, func(a, b domain.ID) int { return strings.Compare(a.String(), b.String()) })
	return boards, nil
}

// backupRequiredMessage は除外説明を元予約event/他backup署名と区別する。
func backupRequiredMessage(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return append([]byte("oimo/backup-required-original-holds-omission/v1\x00"), h[:]...)
}

// encodeBackupRequiredOmission は本文なしの板集合/捕捉site版を別用途署名へ束縛する。
func encodeBackupRequiredOmission(id, site domain.ID, seq domain.U64, at domain.Time, boards []domain.ID, key ed25519.PrivateKey) ([]byte, error) {
	p := backupRequiredOmission{"required-original-holds-backup-omission-v1", id, site, seq, at, boards, "ordinary_backup_scope_excluded"}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	return json.Marshal(backupOptionalEnvelope{raw, base64.StdEncoding.EncodeToString(ed25519.Sign(key, backupRequiredMessage(raw)))})
}

// addRequiredOmission は停止中siteの除外を生成し、新manifest形式と全体byte予算へ計上する。
func (p *backupPlan) addRequiredOmission(root string, entry *backupEntry) error {
	state, e := inspectRuntimeControl(root, "site", p.manifest.Site)
	if e != nil {
		return e
	}
	boards, e := backupRequiredBoards(state, p.manifest.Site)
	if e != nil || len(boards) == 0 {
		return e
	}
	seed, e := readPrivate(filepath.Join(root, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	raw, e := encodeBackupRequiredOmission(p.manifest.ID, p.manifest.Site, state.Seq, entry.Captured, boards, key)
	if e != nil {
		return e
	}
	f := backupFile{backupRequiredOmissionName, domain.U64(len(raw)), sha256.Sum256(raw)}
	if e = p.addSource(backupSource{target: backupEntryPath(*entry) + "/" + f.Name, file: f, generated: raw}); e != nil {
		return e
	}
	entry.Files = append(entry.Files, f)
	p.manifest.RequiredHoldsOmitted = true
	return nil
}

// verifyRequiredOmissionPayload は署名/完全型と全板集合をsite捕捉境界へ照合する。
func verifyRequiredOmissionPayload(raw []byte, m backupManifest, state store.ControlState, at domain.Time, public ed25519.PublicKey) error {
	p, e := decodeSignedRequiredOmission(raw, public)
	if e != nil {
		return e
	}
	boards, e := backupRequiredBoards(state, m.Site)
	if e != nil {
		return e
	}
	if !validRequiredOmissionHeader(p, m, state.Seq, at) || len(boards) == 0 || !slices.Equal(p.Boards, boards) {
		return errors.New("backup required-original omission boundary mismatch")
	}
	for _, cut := range m.ControlCut {
		if cut.Kind == "site" && cut.Owner == m.Site && cut.Sequence == p.Sequence {
			return nil
		}
	}
	return store.ErrCorrupt
}

// decodeSignedRequiredOmission は完全型と専用用途署名を確認する。公開鍵は外部認証済みのものを渡す。
func decodeSignedRequiredOmission(raw []byte, public ed25519.PublicKey) (backupRequiredOmission, error) {
	var env backupOptionalEnvelope
	var p backupRequiredOmission
	if len(raw) > backupRequiredOmissionLimit || strictjson.Decode(raw, &env) != nil || strictjson.Decode(env.Payload, &p) != nil {
		return p, store.ErrCorrupt
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != env.Signature || !ed25519.Verify(public, backupRequiredMessage(env.Payload), sig) {
		return p, errors.New("backup required-original omission signature mismatch")
	}
	return p, nil
}

// validRequiredOmissionHeader は本文なし説明をbackup ID・site捕捉版/時刻・固定用途へ束縛する。
func validRequiredOmissionHeader(p backupRequiredOmission, m backupManifest, seq domain.U64, at domain.Time) bool {
	return p.Schema == "required-original-holds-backup-omission-v1" && p.Backup == m.ID && p.Site == m.Site && p.Sequence == seq && p.Captured == at && p.Reason == "ordinary_backup_scope_excluded"
}

// requiredOmissionBoundary は除外file/manifest/site板集合の三者を照合する。
func requiredOmissionBoundary(m backupManifest, state store.ControlState) (backupEntry, bool, error) {
	meta, found := requiredOmissionMetadata(m)
	boards, e := backupRequiredBoards(state, m.Site)
	if e != nil {
		return meta, false, e
	}
	if (len(boards) > 0) != m.RequiredHoldsOmitted || found != m.RequiredHoldsOmitted {
		return meta, false, errors.New("backup required-original omission declaration missing or unexpected")
	}
	return meta, found, nil
}

// requiredOmissionMetadata はmanifestの既知metadata内だけで除外説明を探す。
func requiredOmissionMetadata(m backupManifest) (backupEntry, bool) {
	for _, entry := range m.Entries {
		if entry.Kind != "metadata" {
			continue
		}
		for _, f := range entry.Files {
			if f.Name == backupRequiredOmissionName {
				return entry, true
			}
		}
		return entry, false
	}
	return backupEntry{}, false
}

// verifyRequiredOmissionAt は別途認証したinstance公開鍵で、署名説明だけを検査する。
func verifyRequiredOmissionAt(dir string, rawPath string, m backupManifest, state store.ControlState, at domain.Time) error {
	markerRaw, e := readPrivate(filepath.Join(dir, "instance.json"), 4096)
	if e != nil {
		return e
	}
	var marker instance
	if strictjson.Decode(markerRaw, &marker) != nil || marker.SiteID != m.Site {
		return store.ErrCorrupt
	}
	raw, e := readPrivate(rawPath, backupRequiredOmissionLimit)
	if e != nil {
		return e
	}
	return verifyRequiredOmissionPayload(raw, m, state, at, ed25519.PublicKey(marker.SigningPublic[:]))
}

// verifyBackupRequiredOmission は通常backupの捕捉済みsiteと認証済みmetadataを照合する。
func verifyBackupRequiredOmission(ctx context.Context, root string, m backupManifest) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	var siteEntry backupEntry
	for _, entry := range m.Entries {
		if entry.Kind == "site" {
			siteEntry = entry
		}
	}
	state, e := store.InspectControlWithValidators(filepath.Join(root, filepath.FromSlash(backupEntryPath(siteEntry))), 1, m.Site, 0, validateSiteValue, snapshotSiteValue)
	if e != nil {
		return e
	}
	meta, found, e := requiredOmissionBoundary(m, state)
	if e != nil || !found {
		return e
	}
	dir := filepath.Join(root, filepath.FromSlash(backupEntryPath(meta)))
	return verifyRequiredOmissionAt(dir, filepath.Join(dir, backupRequiredOmissionName), m, state, meta.Captured)
}

// verifyReplayRequiredOmission は隔離再生の除外説明を照合する。製品起動の欠落補完は許可しない。
func verifyReplayRequiredOmission(root string, m backupManifest, state store.ControlState) error {
	meta, found, e := requiredOmissionBoundary(m, state)
	if e != nil || !found {
		return e
	}
	return verifyRequiredOmissionAt(root, filepath.Join(root, "reports", backupRequiredOmissionName), m, state, meta.Captured)
}
