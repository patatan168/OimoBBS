// 再生用rootの位置・inode・捕捉物・限定journal日付を用途別MACへ束縛する。
package bootstrap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const replayCleanupLimit = backupManifestLimit + 16384

type replayCleanupPlan struct {
	Schema      uint32         `json:"schema"`
	Mode        string         `json:"mode"`
	Root        string         `json:"root"`
	Device      domain.U64     `json:"device"`
	Inode       domain.U64     `json:"inode"`
	Created     domain.Time    `json:"created_at_ns"`
	BackupSHA   domain.Hash    `json:"backup_manifest_sha256"`
	Backup      backupManifest `json:"backup"`
	JournalDays []domain.U64   `json:"journal_days"`
}

func replayCleanupKey(root string) (domain.Hash, error) {
	master, e := readPrivate(filepath.Join(root, "keys/master-000001.key"), 32)
	if e != nil {
		return domain.Hash{}, e
	}
	defer clear(master)
	return identity.DeriveKey(master, "backup_replay_cleanup", 1)
}
func replayRootIdentity(root string) (domain.U64, domain.U64, error) {
	if e := privatePath(root, true); e != nil {
		return 0, 0, e
	}
	info, e := os.Stat(root)
	if e != nil {
		return 0, 0, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("unsupported replay root identity")
	}
	return domain.U64(st.Dev), domain.U64(st.Ino), nil
}

// writeReplayCleanupPlan は鍵を複写する前に、既存root専用の認証済み回収境界を同期する。
func writeReplayCleanupPlan(root, keys string, m backupManifest, sha domain.Hash, at time.Time) (replayCleanupPlan, error) {
	dev, inode, e := replayRootIdentity(root)
	if e != nil {
		return replayCleanupPlan{}, e
	}
	today := time.Now().UTC()
	days := []domain.U64{}
	for _, d := range []time.Time{today, today.AddDate(0, 0, 1)} {
		n, _ := strconv.ParseUint(d.Format("20060102"), 10, 64)
		days = append(days, domain.U64(n))
	}
	p := replayCleanupPlan{1, "verification_only", root, dev, inode, domain.Time(at.UnixNano()), sha, m, days}
	key, e := replayCleanupKey(keys)
	if e != nil {
		return replayCleanupPlan{}, e
	}
	defer clear(key[:])
	raw, e := encodeReplayCleanupPlan(p, key)
	if e != nil {
		return replayCleanupPlan{}, e
	}
	if e = writeNew(filepath.Join(root, backupReplayGate), raw); e != nil {
		return replayCleanupPlan{}, e
	}
	return p, errors.Join(store.SyncDirectory(root), store.SyncDirectory(filepath.Dir(root)))
}
func validateReplayCleanupPlan(p replayCleanupPlan) error {
	if p.Schema != 1 || p.Mode != "verification_only" || !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root || !strings.HasPrefix(filepath.Base(p.Root), ".backup-replay-") || !safeBackupName(filepath.Base(p.Root)) || p.Inode == 0 || p.Created < p.Backup.Created || p.Created >= p.Backup.Expires || p.BackupSHA == (domain.Hash{}) || len(p.JournalDays) != 2 {
		return errors.New("invalid replay cleanup plan")
	}
	if _, e := validateBackupManifest(p.Backup); e != nil {
		return e
	}
	first, e := time.Parse("20060102", strconv.FormatUint(uint64(p.JournalDays[0]), 10))
	if e != nil {
		return errors.New("invalid replay cleanup journal day")
	}
	if first.AddDate(0, 0, 1).Format("20060102") != strconv.FormatUint(uint64(p.JournalDays[1]), 10) {
		return errors.New("invalid replay cleanup journal range")
	}
	_, _, e = replayCleanupInventory(p)
	return e
}
func encodeReplayCleanupPlan(p replayCleanupPlan, key domain.Hash) ([]byte, error) {
	if e := validateReplayCleanupPlan(p); e != nil {
		return nil, e
	}
	payload, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(backupEnvelope{payload, sha256.Sum256(payload), identity.MAC(key[:], "oimo/backup-replay-cleanup/v1", payload)})
	if e == nil && len(raw) > replayCleanupLimit {
		e = errors.New("replay cleanup plan budget exceeded")
	}
	return raw, e
}
func decodeReplayCleanupPlan(raw []byte, key domain.Hash) (replayCleanupPlan, error) {
	var p replayCleanupPlan
	var env backupEnvelope
	if len(raw) > replayCleanupLimit {
		return p, errors.New("replay cleanup plan budget exceeded")
	}
	if e := strictjson.Decode(raw, &env); e != nil {
		return p, e
	}
	mac := identity.MAC(key[:], "oimo/backup-replay-cleanup/v1", env.Manifest)
	if sha256.Sum256(env.Manifest) != env.SHA || !hmac.Equal(mac[:], env.MAC[:]) {
		return p, errors.New("replay cleanup plan authentication failed")
	}
	if e := strictjson.Decode(env.Manifest, &p); e != nil {
		return p, e
	}
	return p, validateReplayCleanupPlan(p)
}

// replayCleanupInventory は本文を読まず、捕捉物と復旧が生成し得る固定集合だけを許可する。
func replayCleanupInventory(p replayCleanupPlan) (map[string]bool, map[string]bool, error) {
	files := map[string]bool{backupReplayGate: true, independentReplayGate: true, ".lock": true}
	dirs := map[string]bool{".": true, "keys": true}
	for _, name := range emptyDirectories {
		dirs[name] = true
	}
	add := func(name string) {
		files[name] = true
		for d := filepath.ToSlash(filepath.Dir(name)); d != "."; d = filepath.ToSlash(filepath.Dir(d)) {
			dirs[d] = true
		}
	}
	for _, name := range backupKeyNames[1:] {
		add(name)
	}
	for _, entry := range p.Backup.Entries {
		for _, f := range entry.Files {
			target, e := backupReplayTarget(entry, f.Name)
			if e != nil {
				return nil, nil, e
			}
			add(target)
		}
		if entry.Kind != "board" {
			continue
		}
		dirs["boards/"+entry.Owner.String()+"/threads"] = true
		for _, day := range p.JournalDays {
			prefix := "evidence/" + entry.Owner.String() + "/" + strconv.FormatUint(uint64(day), 10) + "/"
			add(prefix + "control.current")
			add(prefix + "control-000001.wal")
		}
	}
	if len(files) > backupFileLimit+4*maxPersistentBoards+5 {
		return nil, nil, errors.New("replay cleanup inventory budget exceeded")
	}
	return files, dirs, nil
}
