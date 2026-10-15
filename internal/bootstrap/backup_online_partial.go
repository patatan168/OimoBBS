// オンラインコピーの予定集合をpayload前に署名し、正本不要の期限切れ回収へ接続する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type onlinePartialPlan struct {
	Schema   uint32              `json:"schema"`
	Mode     string              `json:"mode"`
	Root     string              `json:"root"`
	Plan     string              `json:"plan_file"`
	Device   domain.U64          `json:"device"`
	Inode    domain.U64          `json:"inode"`
	Site     domain.ID           `json:"site_id"`
	TrustSHA domain.Hash         `json:"trust_sha256"`
	Created  domain.Time         `json:"created_at_ns"`
	Expires  domain.Time         `json:"expires_at_ns"`
	Files    []onlinePlannedFile `json:"files"`
}
type onlinePlannedFile struct {
	Name   string     `json:"file"`
	Length domain.U64 `json:"max_length"`
}

func onlineInventoryMessage(hash domain.Hash) []byte {
	return append([]byte("oimo/online-backup-inventory/v2\x00"), hash[:]...)
}

func (s *partialBackupSigner) saveOnline(ctx context.Context, g *OnlineBackupGroup, site domain.ID, started time.Time) error {
	dev, inode, e := replayRootIdentity(s.root)
	if e != nil {
		return e
	}
	p := onlinePartialPlan{Schema: 2, Mode: "online_inventory_cleanup", Root: s.root, Plan: s.plan, Device: dev, Inode: inode, Site: site, TrustSHA: s.trustSHA, Created: domain.Time(started.UnixNano()), Expires: domain.Time(started.Add(backupRetention).UnixNano())}
	for _, part := range g.parts {
		cut, e := part.pin.Preview()
		if e != nil {
			return e
		}
		if cut.Expires != 0 {
			p.Expires = min(p.Expires, cut.Expires)
		}
		prefix := "owners/" + part.kind + "/" + part.owner.String() + "/" + part.subkey + "/"
		for _, file := range cut.Files {
			p.Files = append(p.Files, onlinePlannedFile{prefix + file.Name, file.Length})
		}
		p.Files = append(p.Files, onlinePlannedFile{prefix + cut.CurrentName, domain.U64(len(cut.Current))})
	}
	for name, raw := range g.metadata {
		p.Files = append(p.Files, onlinePlannedFile{"owners/metadata/" + site.String() + "/bootstrap/" + name, domain.U64(len(raw))})
	}
	p.Files = append(p.Files, onlinePlannedFile{"manifest.pending", backupManifestLimit}, onlinePlannedFile{"manifest.json", backupManifestLimit})
	if e = validateOnlinePartial(p); e != nil {
		return e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	hash := sha256.Sum256(raw)
	encoded, e := json.Marshal(backupKeysPlanEnvelope{Plan: raw, SHA: hash, SigningKeyID: 10, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, onlineInventoryMessage(hash)))})
	if e != nil {
		return e
	}
	if len(encoded) > backupPartialPlanLimit {
		return store.ErrHistoryBudget
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = writeNew(s.plan, encoded); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(s.plan))
}

func validateOnlinePartial(p onlinePartialPlan) error {
	if (p.Schema != 2 || p.Mode != "online_inventory_cleanup") || p.Site == (domain.ID{}) || p.Inode == 0 || p.Created <= 0 || p.Expires <= p.Created || p.Expires-p.Created > domain.Time(backupRetention) || !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root || !filepath.IsAbs(p.Plan) || filepath.Clean(p.Plan) != p.Plan || p.TrustSHA == (domain.Hash{}) || len(p.Files) == 0 || len(p.Files) > backupFileLimit {
		return errors.New("invalid online partial plan")
	}
	seen := map[string]bool{}
	for _, f := range p.Files {
		if !safeBackupName(f.Name) || f.Length == 0 || uint64(f.Length) > backupByteLimit || seen[f.Name] {
			return store.ErrCorrupt
		}
		seen[f.Name] = true
	}
	return nil
}

// ReclaimOnlinePartialBackup は署名済み予定集合だけを期限切れ時に回収する。
// v1は完成印を拒否し、v2は事前に許可した完成印を含む。復元可能性は判定しない。
// 正本や秘密鍵は不要。既定apply=falseで、途中出力を認証してから対象を限定する。
func ReclaimOnlinePartialBackup(ctx context.Context, input, trust, plan string, apply bool) (BackupReport, error) {
	return reclaimOnlinePartial(ctx, input, trust, plan, apply, time.Now)
}
func reclaimOnlinePartial(ctx context.Context, input, trust, plan string, apply bool, clock func() time.Time) (report BackupReport, err error) {
	if err = backupKeysPlanPaths(input, trust, plan); err != nil {
		return report, err
	}
	marker, trustRaw, e := loadBackupTrust(trust)
	if e != nil {
		return report, e
	}
	raw, e := readPrivate(plan, backupPartialPlanLimit)
	if e != nil {
		return report, e
	}
	var env backupKeysPlanEnvelope
	if e = strictjson.Decode(raw, &env); e != nil {
		return report, e
	}
	var p onlinePartialPlan
	if e = strictjson.Decode(env.Plan, &p); e != nil {
		return report, e
	}
	message := onlineInventoryMessage(env.SHA)
	sig, e := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if e != nil || env.Retired || env.SigningKeyID != 10 || sha256.Sum256(env.Plan) != env.SHA || !ed25519.Verify(ed25519.PublicKey(marker.SigningPublic[:]), message, sig) {
		return report, errors.New("online partial signature rejected")
	}
	if e = validateOnlinePartial(p); e != nil {
		return report, e
	}
	dev, inode, e := replayRootIdentity(input)
	if e != nil {
		return report, e
	}
	if p.Root != input || p.Plan != plan || p.Device != dev || p.Inode != inode || p.Site != marker.SiteID || p.TrustSHA != sha256.Sum256(trustRaw) {
		return report, errors.New("online partial identity mismatch")
	}
	if clock().UnixNano() < int64(p.Created) {
		return report, errors.New("online partial clock regression")
	}
	files, dirs := map[string]bool{}, map[string]bool{".": true}
	for _, f := range p.Files {
		files[f.Name] = true
		for dir := filepath.ToSlash(filepath.Dir(f.Name)); dir != "."; dir = filepath.ToSlash(filepath.Dir(dir)) {
			dirs[dir] = true
		}
		if e = partialBackupLength(filepath.Join(input, filepath.FromSlash(f.Name)), f.Length); e != nil {
			return report, e
		}
	}
	if e = walkBackupInventory(ctx, input, files, dirs, true); e != nil {
		return report, e
	}
	report.Expires = p.Expires
	report.Expired = clock().UnixNano() >= int64(p.Expires)
	if !apply || !report.Expired {
		return report, nil
	}
	markerName := "manifest.pending"
	if files["manifest.json"] {
		markerName = "manifest.json"
	}
	if e = reclaimBackupInventoryWithMissingManifest(ctx, input, files, dirs, markerName, true, func(stage string) error {
		if stage == "backup:reclaim_manifest" {
			return retireBackupCleanupPlan(plan, raw, backupPartialPlanLimit)
		}
		return nil
	}); e != nil {
		return report, e
	}
	report.Applied = true
	return report, nil
}
