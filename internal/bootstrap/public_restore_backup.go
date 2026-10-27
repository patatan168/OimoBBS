// 最新の制御・currentを保ったまま、認証済み旧backupで欠落した本文だけを補完する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// loadRestoreBackup は最新側の鍵・サイト・制御版を検査し、旧候補の全fileを認証する。
func loadRestoreBackup(ctx context.Context, source Config, input string) (backupManifest, error) {
	marker, markerSHA, e := restoreSourceIdentity(source)
	if e != nil {
		return backupManifest{}, e
	}
	key, e := backupKey(source.DataDir)
	if e != nil {
		return backupManifest{}, e
	}
	defer clear(key[:])
	raw, e := readPrivate(filepath.Join(input, "manifest.json"), backupManifestLimit)
	if e != nil {
		return backupManifest{}, e
	}
	m, _, e := decodeBackupManifest(raw, key, marker.SiteID)
	if e != nil {
		return m, e
	}
	if e = backupWindow(time.Now, m.Created, m.Expires); e != nil {
		return m, e
	}
	if e = matchBackupInstance(m, markerSHA); e != nil {
		return m, e
	}
	for _, cut := range m.ControlCut {
		if cut.Kind != "site" && cut.Kind != "board" {
			continue
		}
		latest, e := inspectRuntimeControl(source.DataDir, cut.Kind, cut.Owner)
		if e != nil {
			return m, e
		}
		if latest.Seq < cut.Sequence {
			return m, errors.New("latest control is older than backup")
		}
	}
	if e = verifyBackupFiles(ctx, input, m, true); e != nil {
		return m, e
	}
	return m, nil
}

// restoreSourceIdentity は本文を読まず、最新側の鍵とサイト制御を検査する。
func restoreSourceIdentity(source Config) (marker instance, digest domain.Hash, err error) {
	raw, e := readPrivate(filepath.Join(source.DataDir, "instance.json"), 4096)
	if e != nil {
		return marker, domain.Hash{}, e
	}
	if e = strictjson.Decode(raw, &marker); e != nil {
		return marker, domain.Hash{}, e
	}
	if marker.Schema != storageFormatVersion {
		return marker, domain.Hash{}, errors.New("unsupported restore instance")
	}
	if e = checkKeys(source.DataDir, marker); e != nil {
		return marker, domain.Hash{}, e
	}
	state, e := inspectRuntimeControl(source.DataDir, "site", marker.SiteID)
	if e != nil {
		return marker, domain.Hash{}, e
	}
	if _, e = inspectSiteState(state, marker.SiteID, source.Public.BaseURL); e != nil {
		return marker, domain.Hash{}, e
	}
	return marker, sha256.Sum256(raw), nil
}

// fillRestorePayloads は最新側にcurrentが残るスレッドの参照先だけを補い、旧currentを持ち込まない。
func fillRestorePayloads(ctx context.Context, input, root string, m backupManifest, report *PublicRestoreReport) error {
	for _, entry := range m.Entries {
		if entry.Kind != "thread" {
			continue
		}
		if e := fillRestoreThread(ctx, input, root, entry, m.Site, report); e != nil {
			return e
		}
	}
	return backupWindow(time.Now, m.Created, m.Expires)
}

// fillRestoreThread は最新currentの参照ファイルを補い、最新の確定操作を反映する。
func fillRestoreThread(ctx context.Context, input, root string, entry backupEntry, site domain.ID, report *PublicRestoreReport) error {
	relative, e := backupReplayTarget(entry, "current.json")
	if e != nil {
		return e
	}
	raw, e := readPrivate(filepath.Join(root, relative), 16<<10)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	latest, e := store.DecodeCurrent(raw)
	if e != nil {
		return e
	}
	if latest.BoardID != entry.Owner || strconv.FormatUint(uint64(latest.ThreadKey), 10) != entry.Subkey {
		return errors.New("restore current owner mismatch")
	}
	filled := false
	for _, file := range entry.Files {
		if file.Name != latest.Delta.File && (latest.Base == nil || file.Name != latest.Base.File) {
			continue
		}
		target := filepath.Join(filepath.Dir(filepath.Join(root, relative)), file.Name)
		if _, e = os.Lstat(target); e == nil {
			continue
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		source := filepath.Join(input, filepath.FromSlash(backupEntryPath(entry)), file.Name)
		if e = matchRestorePayload(ctx, source, file, latest); e != nil {
			return e
		}
		count, e := copyRestoreFile(ctx, source, target)
		if e != nil {
			return e
		}
		if e = matchRestorePayload(ctx, target, file, latest); e != nil {
			return e
		}
		report.PayloadFilesRecovered++
		report.Files++
		report.Bytes += count
		filled = true
	}
	if filled {
		if e = catchUpRestoreThread(ctx, root, entry, site); e != nil {
			return e
		}
	}
	return nil
}

// matchRestorePayload は候補の全hashと最新currentの必須prefixを読み直して照合する。
func matchRestorePayload(ctx context.Context, path string, file backupFile, latest store.Manifest) (err error) {
	actual, e := store.HashBackupFile(ctx, path)
	if e != nil {
		return e
	}
	if actual.Length != file.Length || actual.SHA != file.SHA {
		return errors.New("restore payload checksum mismatch")
	}
	if latest.Base != nil && file.Name == latest.Base.File {
		if file.Length != latest.Base.Length || file.SHA != latest.Base.SHA {
			return errors.New("old backup cannot supply latest pack")
		}
		return nil
	}
	if file.Length < latest.Delta.RequiredEnd {
		return errors.New("old backup cannot supply latest WAL prefix")
	}
	in, e := os.Open(path)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, in.Close()) }()
	hash := sha256.New()
	if _, e = io.CopyN(hash, in, int64(latest.Delta.RequiredEnd)); e != nil {
		return e
	}
	if string(hash.Sum(nil)) != string(latest.Delta.RequiredSHA[:]) {
		return errors.New("old backup WAL prefix differs from latest current")
	}
	return nil
}

// catchUpRestoreThread は作業先の最新署名列だけを読み、受理済みの不足frameを反映する。
func catchUpRestoreThread(ctx context.Context, root string, entry backupEntry, site domain.ID) error {
	seed, e := readPrivate(filepath.Join(root, "keys/evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	dir := filepath.Join(root, "evidence", entry.Owner.String())
	days, e := postingNames(dir)
	if e != nil {
		return e
	}
	entries := []evidence.Entry{}
	bytesHeld := 0
	defer func() {
		for _, v := range entries {
			clear(v.Payload)
		}
	}()
	validator := app.PostingValidator(bindPostingCapture(postcapture.Validate, site, entry.Owner))
	for _, day := range days {
		if e = ctx.Err(); e != nil {
			return e
		}
		_, e = evidence.VisitJournalReadOnly(filepath.Join(dir, strconv.FormatUint(day, 10)), entry.Owner, day, 10, key, validator, func(v evidence.Entry) error {
			// 全列は検証するが、このスレッドの固定操作だけを保持する。
			var link struct {
				Thread domain.U64 `json:"thread_key"`
			}
			if e := json.Unmarshal(v.Payload, &link); e != nil {
				return e
			}
			if strconv.FormatUint(uint64(link.Thread), 10) == entry.Subkey {
				bytesHeld += len(v.Payload)
				if len(entries) >= 8192 || bytesHeld > 32<<20 {
					return errors.New("restore thread signature budget exceeded")
				}
				v.Payload = bytes.Clone(v.Payload)
				entries = append(entries, v)
			}
			return nil
		})
		if e != nil {
			return e
		}
	}
	thread, e := strconv.ParseUint(entry.Subkey, 10, 64)
	if e != nil {
		return e
	}
	return app.RestoreAcceptedPostingFrames(ctx, filepath.Join(root, "boards", entry.Owner.String(), "threads"), entry.Owner, thread, entries)
}
