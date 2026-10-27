// 停止中バックアップの所有境界・期限・ファイル集合を用途別MACへ束縛する。
package bootstrap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path"
	"path/filepath"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
)

const backupManifestLimit = 32 << 20
const backupFileLimit = 100000
const backupByteLimit uint64 = 16 << 30
const backupRetention = 24 * time.Hour

// BackupReport は本文・鍵を含まない停止中バックアップの結果。RestoreReadyはこの工程ではfalse。
// 除外欄はHTTPログ/必須予約履歴が通常backupの捕捉範囲外で、独立復元が必要なことを示す。
type BackupReport struct {
	DeletionReportsOmitted       bool        `json:"deletion_reports_omitted"`
	ID                           domain.ID   `json:"backup_id"`
	Owners                       int         `json:"owner_count"`
	Files                        int         `json:"file_count"`
	Bytes                        domain.U64  `json:"bytes"`
	Expires                      domain.Time `json:"expires_at_ns"`
	Verified                     bool        `json:"verified"`
	Replayed                     bool        `json:"replayed"`
	RestoreReady                 bool        `json:"restore_ready"`
	Expired                      bool        `json:"expired"`
	Applied                      bool        `json:"applied"`
	OptionalHTTPLogsOmitted      bool        `json:"optional_http_logs_omitted"`
	RequiredOriginalHoldsOmitted bool        `json:"required_original_holds_omitted"`
}
type backupManifest struct {
	DeletionReportsOmitted  bool          `json:"deletion_reports_omitted"`
	OptionalHTTPLogsOmitted bool          `json:"optional_http_logs_omitted"`
	RequiredHoldsOmitted    bool          `json:"required_original_holds_omitted"`
	Schema                  uint32        `json:"schema"`
	Mode                    string        `json:"mode"`
	ID                      domain.ID     `json:"id"`
	Created                 domain.Time   `json:"created_at_ns"`
	Expires                 domain.Time   `json:"expires_at_ns"`
	Site                    domain.ID     `json:"site_id"`
	MinimumReader           uint32        `json:"minimum_reader_version"`
	ControlCut              []backupCut   `json:"control_cut"`
	Entries                 []backupEntry `json:"entries"`
	KeyIDs                  []uint32      `json:"key_ids"`
}
type backupCut struct {
	Kind     string     `json:"kind"`
	Owner    domain.ID  `json:"owner_id"`
	Sequence domain.U64 `json:"seq"`
}
type backupEntry struct {
	Kind             string       `json:"kind"`
	Owner            domain.ID    `json:"owner_id"`
	Subkey           string       `json:"subkey"`
	Captured         domain.Time  `json:"captured_at_ns"`
	Sequence         domain.U64   `json:"captured_seq"`
	RequiredEnd      domain.U64   `json:"required_end"`
	OriginalExpires  domain.Time  `json:"original_expires_at_ns"`
	PublicationEpoch domain.U64   `json:"publication_epoch"`
	Files            []backupFile `json:"files"`
}
type backupFile struct {
	Name   string      `json:"file"`
	Length domain.U64  `json:"length"`
	SHA    domain.Hash `json:"sha256"`
}
type backupEnvelope struct {
	Manifest json.RawMessage `json:"manifest"`
	SHA      domain.Hash     `json:"manifest_sha256"`
	MAC      domain.Hash     `json:"manifest_mac"`
}

func backupKey(root string) (domain.Hash, error) {
	master, e := readPrivate(filepath.Join(root, "keys", "master-000001.key"), 32)
	if e != nil {
		return domain.Hash{}, e
	}
	defer clear(master)
	return identity.DeriveKey(master, "backup_manifest", 1)
}

// safeBackupName はOS解釈の差を避け、dot segment・絶対path・区切りの別表記を拒否する。
func safeBackupName(name string) bool {
	if name == "" || len(name) > 512 || path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	for _, p := range strings.Split(name, "/") {
		if p == "." || p == ".." || len(p) > 128 {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}
func backupEntryPath(e backupEntry) string {
	return "owners/" + e.Kind + "/" + e.Owner.String() + "/" + e.Subkey
}

func encodeBackupManifest(m backupManifest, key domain.Hash) ([]byte, error) {
	if _, e := validateBackupManifest(m); e != nil {
		return nil, e
	}
	payload, e := json.Marshal(m)
	if e != nil {
		return nil, e
	}
	envelope := backupEnvelope{payload, sha256.Sum256(payload), identity.MAC(key[:], "oimo/backup-manifest/v1", payload)}
	raw, e := json.Marshal(envelope)
	if e == nil && len(raw) > backupManifestLimit {
		e = errors.New("backup manifest budget exceeded")
	}
	return raw, e
}
func decodeBackupManifest(raw []byte, key domain.Hash, site domain.ID) (backupManifest, BackupReport, error) {
	var envelope backupEnvelope
	var m backupManifest
	if e := strictjson.Decode(raw, &envelope); e != nil {
		return m, BackupReport{}, e
	}
	mac := identity.MAC(key[:], "oimo/backup-manifest/v1", envelope.Manifest)
	if sha256.Sum256(envelope.Manifest) != envelope.SHA || !hmac.Equal(mac[:], envelope.MAC[:]) {
		return m, BackupReport{}, errors.New("backup manifest authentication failed")
	}
	if e := strictjson.Decode(envelope.Manifest, &m); e != nil {
		return m, BackupReport{}, e
	}
	report, e := validateBackupManifest(m)
	if e == nil && m.Site != site {
		e = errors.New("backup belongs to another site")
	}
	return m, report, e
}

func validateBackupManifest(m backupManifest) (BackupReport, error) {
	fail := func() (BackupReport, error) { return BackupReport{}, errors.New("invalid backup manifest") }
	if (m.Schema != 7 || m.Mode != "offline_candidate" && m.Mode != "online_candidate") || m.ID == (domain.ID{}) || m.Site == (domain.ID{}) || m.Created <= 0 || m.Expires <= m.Created || int64(m.Expires-m.Created) > int64(backupRetention) || m.MinimumReader < 1 || m.MinimumReader > readerVersion || len(m.KeyIDs) != 2 || m.KeyIDs[0] != 1 || m.KeyIDs[1] != 10 || len(m.Entries) == 0 || len(m.Entries) > backupFileLimit {
		return fail()
	}
	if m.DeletionReportsOmitted && m.MinimumReader < 62 {
		return fail()
	}
	report := BackupReport{DeletionReportsOmitted: m.DeletionReportsOmitted, ID: m.ID, Owners: len(m.Entries), Expires: m.Expires, OptionalHTTPLogsOmitted: backupOptionalDeclared(m), RequiredOriginalHoldsOmitted: m.RequiredHoldsOmitted}
	seen := map[string]bool{}
	for _, entry := range m.Entries {
		if e := validateBackupEntry(m, entry); e != nil {
			return BackupReport{}, e
		}
		prefix := backupEntryPath(entry)
		if seen[prefix] {
			return fail()
		}
		seen[prefix] = true
		for _, file := range entry.Files {
			name := prefix + "/" + file.Name
			if !safeBackupName(file.Name) || seen[name] || file.SHA == (domain.Hash{}) || uint64(file.Length) > backupByteLimit-uint64(report.Bytes) {
				return fail()
			}
			seen[name] = true
			report.Bytes += file.Length
			report.Files++
			if report.Files > backupFileLimit {
				return fail()
			}
		}
	}
	if e := validateBackupCuts(m, seen); e != nil {
		return BackupReport{}, e
	}
	return report, nil
}
func validateBackupEntry(m backupManifest, e backupEntry) error {
	if e.Owner == (domain.ID{}) || !safeBackupName(e.Subkey) || strings.Contains(e.Subkey, "/") || e.Captured < m.Created || e.Captured >= m.Expires || e.PublicationEpoch != 0 || len(e.Files) == 0 || (e.OriginalExpires != 0 && e.OriginalExpires < m.Expires) {
		return errors.New("invalid backup owner boundary")
	}
	switch e.Kind {
	case "site", "board", "thread", "evidence", "audit", "job", "deletion":
		if e.Sequence == 0 || e.RequiredEnd < 64 {
			return errors.New("invalid backup sequence")
		}
	case "metadata":
		if e.Owner != m.Site || e.Subkey != "bootstrap" || e.Sequence != 0 || e.RequiredEnd != 0 || e.OriginalExpires != 0 {
			return errors.New("invalid backup metadata")
		}
	default:
		return errors.New("unknown backup owner kind")
	}
	if e.Kind == "site" && (e.Owner != m.Site || e.Subkey != "control") || e.Kind == "board" && (e.Owner == m.Site || e.Subkey != "control") || e.Kind == "thread" && e.OriginalExpires == 0 {
		return errors.New("invalid backup owner relationship")
	}
	return nil
}
func validateBackupCuts(m backupManifest, entries map[string]bool) error {
	seen := map[string]bool{}
	sequences := map[string]domain.U64{}
	for _, entry := range m.Entries {
		if entry.Kind == "site" || entry.Kind == "board" {
			sequences[backupEntryPath(entry)] = entry.Sequence
		}
	}
	for _, cut := range m.ControlCut {
		name := "owners/" + cut.Kind + "/" + cut.Owner.String() + "/control"
		if (cut.Kind != "site" && cut.Kind != "board") || seen[name] || !entries[name] {
			return errors.New("invalid backup control cut")
		}
		seen[name] = true
		if sequences[name] != cut.Sequence {
			return errors.New("backup control sequence mismatch")
		}

	}
	for _, e := range m.Entries {
		if (e.Kind == "site" || e.Kind == "board") && !seen[backupEntryPath(e)] {
			return errors.New("missing backup control cut")
		}
		if e.Kind == "thread" || e.Kind == "evidence" {
			if !seen["owners/board/"+e.Owner.String()+"/control"] {
				return errors.New("backup has no board owner")
			}
		}
	}
	if !seen["owners/site/"+m.Site.String()+"/control"] {
		return errors.New("missing backup site")
	}
	return nil
}

// backupOptionalDeclared は現行manifestの明示的なHTTPログ除外宣言を返す。
func backupOptionalDeclared(m backupManifest) bool {
	return m.OptionalHTTPLogsOmitted
}
