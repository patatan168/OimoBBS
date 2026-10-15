// 正本不要の隔離コピーを作り、全保存記録を再生照合した後に作業領域を除去する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/platform"
	"oimobbs/internal/store"
)

const backupReplayGate = "backup-replay.json"

// VerifyBackupReplay は別保管鍵を使い、隔離領域で全投稿・署名・制御を再生する。
// workParentは0700の専用親。通常起動を遮断した一時領域を除去し、公開復元の許可を返さない。
func VerifyBackupReplay(ctx context.Context, input, keys, workParent string) (report BackupReport, err error) {
	for _, p := range []string{input, keys} {
		if err = separateBackupPaths(p, workParent); err != nil {
			return report, err
		}
	}
	unlock, e := lockBackupDirectories(filepath.Dir(input), filepath.Dir(keys), workParent)
	if e != nil {
		return report, e
	}
	defer func() {
		err = errors.Join(err, unlock())
		if err != nil {
			report.Verified = false
			report.Replayed = false
		}
	}()
	return verifyBackupReplay(ctx, input, keys, workParent, time.Now, func(string) error { return nil })
}
func verifyBackupReplay(ctx context.Context, input, keys, parent string, clock func() time.Time, checkpoint func(string) error) (report BackupReport, err error) {
	return verifyBackupReplayIndependent(ctx, input, keys, parent, "", clock, checkpoint)
}

// verifyBackupReplayIndependent は任意の独立回収鍵の認証印を本文複写前に同期する。
func verifyBackupReplayIndependent(ctx context.Context, input, keys, parent, cleanupKey string, clock func() time.Time, checkpoint func(string) error) (report BackupReport, err error) {
	defer func() {
		if err != nil {
			report.Verified = false
			report.Replayed = false
		}
	}()
	for _, p := range []string{input, keys} {
		if err = separateBackupPaths(p, parent); err != nil {
			return report, err
		}
	}
	if err = privatePath(parent, true); err != nil {
		return report, err
	}
	report, err = verifyBackupWithKeys(ctx, input, keys, clock)
	if err != nil {
		return report, err
	}
	report.Verified = false
	bundle, err := loadBackupKeys(ctx, keys)
	if err != nil {
		return report, err
	}
	raw, err := readPrivate(filepath.Join(input, "manifest.json"), backupManifestLimit)
	if err != nil {
		return report, err
	}
	key, err := backupKey(keys)
	if err != nil {
		return report, err
	}
	defer clear(key[:])
	if sha256.Sum256(raw) != bundle.BackupSHA {
		return report, errors.New("backup changed before replay")
	}
	m, _, err := decodeBackupManifest(raw, key, bundle.Site)
	if err != nil {
		return report, err
	}
	if m.ID != report.ID || m.Expires != report.Expires || !backupKeysBindingMatches(m, bundle) {
		return report, errors.New("backup binding changed before replay")
	}
	if err = backupCapacity(keys, parent, uint64(report.Bytes)+4096); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	root, err := os.MkdirTemp(parent, ".backup-replay-")
	if err != nil {
		return report, err
	}
	var lock *os.File
	var cleanupPlan *replayCleanupPlan
	defer func() {
		if cleanupPlan != nil {
			err = errors.Join(err, cleanupOwnedReplayRoot(root, *cleanupPlan, func(string) error { return nil }))
		} else {
			// 認証計画の完成前は本文・生鍵を複写していない。
			err = errors.Join(err, os.RemoveAll(root), store.SyncDirectory(parent))
		}
		if lock != nil {
			err = errors.Join(err, platform.Unlock(lock))
		}
		if err == nil {
			err = backupWindow(clock, m.Created, m.Expires)
		}
	}()
	lock, err = platform.Lock(root)
	if err != nil {
		return report, err
	}
	plan, err := writeReplayCleanupPlan(root, keys, m, bundle.BackupSHA, clock())
	if err != nil {
		return report, err
	}
	cleanupPlan = &plan
	if cleanupKey != "" {
		if err = writeIndependentReplayPlan(root, cleanupKey, plan); err != nil {
			return report, err
		}
	}
	if err = materializeBackupReplay(ctx, input, keys, root, m, clock); err != nil {
		return report, err
	}
	if err = checkpoint(root); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupWindow(clock, m.Created, m.Expires); err != nil {
		return report, err
	}
	if err = replayBackupRepository(ctx, root, m); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = backupWindow(clock, m.Created, m.Expires); err != nil {
		return report, err
	}
	report.Verified = true
	report.Replayed = true
	return report, nil
}

// materializeBackupReplay は固定のowner配置へ限定し、入力fileをhardlinkせず複写する。
func materializeBackupReplay(ctx context.Context, input, keys, root string, m backupManifest, clock func() time.Time) error {
	for _, dir := range append([]string{"keys"}, emptyDirectories...) {
		if err := makePrivateDir(filepath.Join(root, dir)); err != nil {
			return err
		}
	}
	for _, entry := range m.Entries {
		for _, file := range entry.Files {
			if err := backupWindow(clock, m.Created, m.Expires); err != nil {
				return err
			}
			target, err := backupReplayTarget(entry, file.Name)
			if err != nil {
				return err
			}
			if err = backupCapacity(keys, root, uint64(file.Length)); err != nil {
				return err
			}
			source := backupSource{source: filepath.Join(input, filepath.FromSlash(backupEntryPath(entry)+"/"+file.Name)), target: target, file: file}
			if err = writeBackupSource(ctx, root, source); err != nil {
				return err
			}
		}
		if entry.Kind == "board" {
			if err := makeBackupDirectories(root, filepath.Join(root, "boards", entry.Owner.String(), "threads")); err != nil {
				return err
			}
		}
	}
	for _, name := range backupKeyNames[1:] {
		if err := ctx.Err(); err != nil {
			return err
		}
		contents, err := readPrivate(filepath.Join(keys, filepath.FromSlash(name)), 32)
		if err != nil {
			return err
		}
		err = writeNew(filepath.Join(root, filepath.FromSlash(name)), contents)
		clear(contents)
		if err != nil {
			return err
		}
	}
	return store.SyncDirectory(filepath.Join(root, "keys"))
}
func backupReplayTarget(entry backupEntry, file string) (string, error) {
	prefix := ""
	switch entry.Kind {
	case "site":
		prefix = "site"
	case "board":
		prefix = "boards/" + entry.Owner.String() + "/control"
	case "thread":
		prefix = "boards/" + entry.Owner.String() + "/threads/" + entry.Subkey
	case "deletion":
		prefix = "expiry/" + entry.Owner.String() + "/" + entry.Subkey
	case "evidence":
		prefix = "evidence/" + entry.Owner.String() + "/" + entry.Subkey
	case "audit":
		prefix = "audit/" + entry.Owner.String() + "/" + entry.Subkey
	case "job":
		prefix = "jobs/" + entry.Owner.String()
	case "metadata":
		if file == "instance.json" {
			return file, nil
		}
		if file == backupRequiredOmissionName {
			return "reports/" + file, nil
		}
		if file == backupOptionalOmissionName {
			return "reports/http/" + file, nil
		}
		if !validReplayAnchor(file) {
			return "", errors.New("unsupported backup replay metadata")
		}
		return file, nil
	default:
		return "", errors.New("unsupported backup replay owner")
	}
	return prefix + "/" + file, nil
}
