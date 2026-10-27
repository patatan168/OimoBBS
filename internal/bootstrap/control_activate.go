// 停止中の認証済み候補を、永続intentの下で全所有者へ再開可能に設置する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// ActivateControlSnapshot はプロセス排他を取得する停止中CLI専用入口。同じ候補で再開する。
// 旧WALは残す。結果不明時はintentを残して通常起動を禁止する。
func ActivateControlSnapshot(ctx context.Context, cfg Config, input string, capture func([]byte) error) (ControlSnapshotReport, error) {
	return activateControlSnapshot(ctx, cfg, input, capture, func(string) {})
}

func activateControlSnapshot(ctx context.Context, cfg Config, input string, capture func([]byte) error, checkpoint func(string)) (out ControlSnapshotReport, retErr error) {
	if err := cfg.validate(); err != nil {
		return ControlSnapshotReport{}, err
	}
	if err := cfg.checkTLS(time.Now()); err != nil {
		return ControlSnapshotReport{}, err
	}
	if capture == nil {
		return ControlSnapshotReport{}, errors.New("posting capture validator required")
	}
	dummy := Repository{cfg: cfg}
	if err := dummy.candidatePath(input); err != nil {
		return ControlSnapshotReport{}, err
	}
	m, err := readCandidateManifest(input)
	if err != nil {
		return ControlSnapshotReport{}, err
	}
	if m.Schema != 2 {
		return ControlSnapshotReport{}, errors.New("activation requires candidate schema 2")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return ControlSnapshotReport{}, err
	}
	hash := sha256.Sum256(raw)
	name := fmt.Sprintf(".control-activation-%s-%x", m.ID, hash)
	intent := filepath.Join(cfg.DataDir, name)
	if _, err = os.Lstat(intent); os.IsNotExist(err) {
		repo, err := OpenPostingRepository(cfg, capture)
		if err != nil {
			return ControlSnapshotReport{}, err
		}
		completed, report, err := alreadyActivated(ctx, repo, input, m)
		if err != nil || completed {
			return report, errors.Join(err, repo.Close())
		}
		var site siteState
		err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site)
		if err == nil && site.MinimumReader < 12 {
			err = errors.New("run control enable-snapshots before preparing a candidate")
		}
		if err == nil {
			_, err = repo.VerifyControlSnapshot(ctx, input)
		}
		if err == nil {
			err = makePrivateDir(intent)
		}
		if err == nil {
			checkpoint("activation_intent")
		}
		err = errors.Join(err, repo.Close())
		if err != nil {
			return ControlSnapshotReport{}, err
		}
	} else if err != nil {
		return ControlSnapshotReport{}, err
	}
	if err = privatePath(cfg.DataDir, true); err != nil {
		return ControlSnapshotReport{}, err
	}
	if err = privatePath(filepath.Join(cfg.DataDir, ".lock"), false); err != nil {
		return ControlSnapshotReport{}, err
	}
	lock, err := platform.Lock(cfg.DataDir)
	if err != nil {
		return ControlSnapshotReport{}, err
	}
	owned := true
	defer func() {
		if owned {
			retErr = errors.Join(retErr, platform.Unlock(lock))
		}
	}()
	if err = requireEmpty(intent); err != nil {
		return ControlSnapshotReport{}, err
	}
	rootNames := append([]string{".lock", "instance.json", "keys", "site", name}, emptyDirectories...)
	rootNames = appendSecurityLogRoot(cfg.DataDir, rootNames)
	if err = requireEntries(cfg.DataDir, rootNames); err != nil {
		return ControlSnapshotReport{}, err
	}
	// mkdir直後のprocess停止から再開した場合も、通常起動禁止を先に同期する。
	if err = store.SyncDirectory(cfg.DataDir); err != nil {
		return ControlSnapshotReport{}, err
	}
	key, err := controlAnchorKey(cfg.DataDir)
	if err != nil {
		return ControlSnapshotReport{}, err
	}
	defer clear(key[:])
	items, err := validateActivation(ctx, cfg, input, m, key)
	if err != nil {
		return ControlSnapshotReport{}, err
	}
	for _, item := range items {
		if err = ctx.Err(); err != nil {
			return ControlSnapshotReport{}, err
		}
		if err = activateOwner(cfg, item, checkpoint); err != nil {
			return ControlSnapshotReport{}, err
		}
		checkpoint("activation_owner")
	}
	// Repository全体（投稿/evidenceも含む）の復旧検査が通るまでintentを外さない。
	owned = false
	repo, err := openLockedPostingRepository(cfg, lock, func(string) {}, capture, name)
	if err != nil {
		return ControlSnapshotReport{}, err
	}
	report := activationReport(m)
	checkpoint("activation_validated")
	err = os.Remove(intent)
	if err == nil {
		err = store.SyncDirectory(cfg.DataDir)
	}
	err = errors.Join(err, repo.Close())
	if err != nil {
		return ControlSnapshotReport{}, err
	}
	return report, nil
}

type activationItem struct {
	owner            candidateOwner
	snapshot, anchor []byte
}

func activationReport(m controlCandidate) ControlSnapshotReport {
	out := ControlSnapshotReport{ID: m.ID, Owners: len(m.Owners), Verified: true, Activated: true}
	for _, item := range m.Owners {
		out.Bytes += item.Length
	}
	return out
}

// alreadyActivated は更新されていない同一候補の完了再実行を無変更で受け付ける。
func alreadyActivated(ctx context.Context, r *Repository, input string, m controlCandidate) (bool, ControlSnapshotReport, error) {
	any := false
	for _, o := range m.Owners {
		if _, ok := r.anchors[o.Owner]; ok {
			any = true
		}
	}
	if !any {
		return false, ControlSnapshotReport{}, nil
	}
	key, err := controlAnchorKey(r.cfg.DataDir)
	if err != nil {
		return false, ControlSnapshotReport{}, err
	}
	defer clear(key[:])
	if m.Site != siteID(r.site.State()) || len(m.Owners) != len(r.boards)+1 {
		return false, ControlSnapshotReport{}, store.ErrCorrupt
	}
	for _, o := range m.Owners {
		log := r.site
		if o.Kind == "board" {
			log = r.boards[o.Owner]
		}
		if log == nil || log.HistoryHeader() != o.header() || log.State().Seq != o.Sequence {
			return false, ControlSnapshotReport{}, errors.New("candidate no longer matches active state")
		}
		path := filepath.Join(controlOwnerPath(r.cfg.DataDir, o.Kind, o.Owner), fmt.Sprintf("control-%06d.anchor.json", o.Generation))
		a, e := readControlAnchor(path, m.Site, m.ID, key)
		if e != nil {
			return false, ControlSnapshotReport{}, e
		}
		if !reflect.DeepEqual(a.Owner, o) {
			return false, ControlSnapshotReport{}, store.ErrCorrupt
		}
	}
	// 完了後も候補の欠落・改変や監査破損を成功扱いしない。
	if _, err = validateActivation(ctx, r.cfg, input, m, key); err != nil {
		return false, ControlSnapshotReport{}, err
	}
	return true, activationReport(m), nil
}

// validateActivation は全所有者を検証し終えるまで設置を開始しない。
func validateActivation(ctx context.Context, cfg Config, input string, m controlCandidate, key domain.Hash) ([]activationItem, error) {
	raw, err := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if err != nil {
		return nil, err
	}
	var marker instance
	if err = strictjson.Decode(raw, &marker); err != nil {
		return nil, err
	}
	if marker.Schema != storageFormatVersion || marker.SiteID != m.Site {
		return nil, store.ErrCorrupt
	}
	if err = checkKeys(cfg.DataDir, marker); err != nil {
		return nil, err
	}
	result := []activationItem{}
	names := []string{"candidate.json"}
	seen := map[domain.ID]bool{}
	repo := Repository{cfg: cfg, anchors: map[domain.ID]candidateOwner{}}
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	archiveBudget := int64(64 << 20)
	var total domain.U64
	for i, o := range m.Owners {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if seen[o.Owner] || o.Generation != 2 || (i == 0 && (o.Kind != "site" || o.Owner != m.Site)) || (i > 0 && o.Kind != "board") {
			return nil, store.ErrCorrupt
		}
		seen[o.Owner] = true
		if err = verifyCandidateAnchor(input, m, o, key); err != nil {
			return nil, err
		}
		total += o.Length
		if total > candidateLimit {
			return nil, store.ErrHistoryBudget
		}
		raw, err = readPrivate(filepath.Join(input, o.File), int64(o.Length))
		if err != nil {
			return nil, err
		}
		anchor, err := readPrivate(filepath.Join(input, anchorFile(o)), anchorLimit)
		if err != nil {
			return nil, err
		}
		path := controlOwnerPath(cfg.DataDir, o.Kind, o.Owner)
		if err = activationLayout(path, o); err != nil {
			return nil, err
		}
		header, e := store.EncodeHeader(o.header())
		if e != nil {
			return nil, e
		}
		for suffix, expected := range map[string][]byte{"snap": raw, "wal": header, "anchor.json": anchor} {
			p := filepath.Join(path, fmt.Sprintf("control-%06d.%s", o.Generation, suffix))
			if e = checkActivationPrefix(p, expected); e != nil {
				return nil, e
			}
		}
		apply := store.ValueValidator(validateSiteValue)
		if o.Kind == "board" {
			apply = validateBoardValue
		}
		log, err := store.OpenControlWithValidators(path, o.header().Kind, o.Owner, 0, apply, snapshotValues(o.Kind))
		if err != nil {
			return nil, err
		}
		repo.anchors[o.Owner] = o
		h := log.HistoryHeader()
		err = func() error {
			if !(h.Generation == 1 && h.BaseSeq == 0) && h != o.header() {
				return store.ErrCorrupt
			}
			if err := verifyCandidateFile(input, o, log.State(), m.Level); err != nil {
				return err
			}
			if o.Kind == "site" {
				site, e := inspectSiteState(log.State(), m.Site, cfg.Public.BaseURL)
				if e != nil {
					return e
				}
				if site.MinimumReader < 12 {
					return store.ErrCorrupt
				}
			}
			report, e := repo.verifyAuditOwner(ctx, o.Owner, o.Kind, log, &budget, &archiveBudget)
			if e != nil {
				return e
			}
			if !report.Complete {
				return store.ErrCorrupt
			}
			return nil
		}()
		err = errors.Join(err, log.Close())
		if err != nil {
			return nil, err
		}
		result = append(result, activationItem{o, raw, anchor})
		names = append(names, o.File, anchorFile(o))
	}
	if err = requireEntries(input, names); err != nil {
		return nil, err
	}
	return result, nil
}

// activationLayout は作業中に作れる名前だけを許可する。旧世代の削除はしない。
func activationLayout(dir string, o candidateOwner) error {
	if err := privatePath(dir, true); err != nil {
		return err
	}
	names, err := activationNames(dir)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err = privatePath(filepath.Join(dir, name), false); err != nil {
			return err
		}
		if name == "control.current" || name == "control-000001.wal" {
			continue
		}
		if strings.HasPrefix(name, ".install-") && len(name) > len(".install-") && strings.Trim(strings.TrimPrefix(name, ".install-"), "0123456789") == "" {
			continue
		}
		gen, ok := controlFileGeneration(name)
		if !ok || gen != uint64(o.Generation) {
			return store.ErrCorrupt
		}
	}
	return nil
}

// completeActivationFile は同じ候補の一致prefixだけを補完する。短い異内容は上書きしない。
func completeActivationFile(path string, want []byte) error {
	got, err := readPrivate(path, int64(len(want)))
	if os.IsNotExist(err) {
		return writeNew(path, want)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want[:len(got)]) {
		return store.ErrCorrupt
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	n, err := f.Write(want[len(got):])
	if err == nil && n != len(want)-len(got) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func activateOwner(cfg Config, item activationItem, checkpoint func(string)) error {
	o := item.owner
	dir := controlOwnerPath(cfg.DataDir, o.Kind, o.Owner)
	path := filepath.Join(dir, fmt.Sprintf("control-%06d.anchor.json", o.Generation))
	if err := completeActivationFile(path, item.anchor); err != nil {
		return err
	}
	if err := store.SyncDirectory(dir); err != nil {
		return err
	}
	checkpoint("activation_anchor")
	apply := store.ValueValidator(validateSiteValue)
	if o.Kind == "board" {
		apply = validateBoardValue
	}
	log, err := store.OpenControlWithValidators(dir, o.header().Kind, o.Owner, 0, apply, snapshotValues(o.Kind))
	if err != nil {
		return err
	}
	if log.HistoryHeader() != o.header() {
		err = log.ResumeSnapshot(item.snapshot).Err
	}
	err = errors.Join(err, log.Close())
	if err != nil {
		return err
	}
	checkpoint("activation_current")
	current, err := readPrivate(filepath.Join(dir, "control.current"), 16<<10)
	if err != nil {
		return err
	}
	names, err := activationNames(dir)
	if err != nil {
		return err
	}
	for _, name := range names {
		if !strings.HasPrefix(name, ".install-") {
			continue
		}
		path := filepath.Join(dir, name)
		raw, e := readPrivate(path, int64(len(current)))
		if e != nil {
			return e
		}
		if !bytes.Equal(raw, current[:len(raw)]) {
			return store.ErrCorrupt
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	return store.SyncDirectory(dir)
}

// activationNames は不正な大量ファイルによる無制限の列挙を避ける。
func activationNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(257)
	if err == io.EOF {
		err = nil
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, err
	}
	if len(names) > 256 {
		return nil, store.ErrHistoryBudget
	}
	return names, nil
}

// checkActivationPrefix は全所有者の設置前に、中断ファイルが同じ候補か検査する。
func checkActivationPrefix(path string, want []byte) error {
	got, err := readPrivate(path, int64(len(want)))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want[:len(got)]) {
		return store.ErrCorrupt
	}
	return nil
}
