// 全検証済み・停止中Repositoryから、現行世代と必要な管理補助記録を列挙する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type backupSource struct {
	source    string
	target    string
	file      backupFile
	generated []byte
}
type backupPlan struct {
	manifest backupManifest
	sources  []backupSource
	bytes    uint64
}

func (r *Repository) planOfflineBackup(ctx context.Context, clock func() time.Time) (backupPlan, error) {
	now := clock()
	var state siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &state); e != nil {
		return backupPlan{}, e
	}
	p := backupPlan{manifest: backupManifest{Schema: 7, Mode: "offline_candidate", ID: domain.NewID(), Created: domain.Time(now.UnixNano()), Expires: domain.Time(now.Add(backupRetention).UnixNano()), Site: state.ID, MinimumReader: state.MinimumReader, KeyIDs: []uint32{1, 10}, Entries: []backupEntry{}, ControlCut: []backupCut{}}}
	_, p.manifest.DeletionReportsOmitted = r.site.State().Rows["report_store:active"]
	if e := p.addControl(ctx, r.cfg.DataDir, "site", state.ID, r.site, clock); e != nil {
		return p, e
	}
	ids := make([]domain.ID, 0, len(r.boards))
	for id := range r.boards {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return strings.Compare(a.String(), b.String()) })
	for _, id := range ids {
		if e := p.addControl(ctx, r.cfg.DataDir, "board", id, r.boards[id], clock); e != nil {
			return p, e
		}
		if e := p.addDeletions(ctx, r.posting[id], clock); e != nil {
			return p, e
		}
		if e := p.addPosting(ctx, r.posting[id], clock); e != nil {
			return p, e
		}
	}
	if e := p.addAudit(ctx, r.cfg.DataDir, clock); e != nil {
		return p, e
	}
	if e := p.addJobs(ctx, r.cfg.DataDir, clock); e != nil {
		return p, e
	}
	if e := p.addMetadata(ctx, r.cfg.DataDir, clock); e != nil {
		return p, e
	}
	_, e := validateBackupManifest(p.manifest)
	return p, e
}

func (p *backupPlan) addCapture(dir, kind string, owner domain.ID, subkey string, cut store.BackupCapture, at time.Time) error {
	entry := backupEntry{Kind: kind, Owner: owner, Subkey: subkey, Captured: domain.Time(at.UnixNano()), Sequence: cut.Sequence, RequiredEnd: cut.RequiredEnd, OriginalExpires: cut.Expires, Files: []backupFile{}}
	if cut.Expires != 0 {
		p.manifest.Expires = min(p.manifest.Expires, cut.Expires)
	}
	prefix := backupEntryPath(entry)
	for _, f := range cut.Files {
		file := backupFile{f.Name, f.Length, f.SHA}
		entry.Files = append(entry.Files, file)
		if err := p.addSource(backupSource{source: filepath.Join(dir, f.Name), target: prefix + "/" + f.Name, file: file}); err != nil {
			return err
		}
	}
	file := backupFile{cut.CurrentName, domain.U64(len(cut.Current)), sha256.Sum256(cut.Current)}
	entry.Files = append(entry.Files, file)
	if err := p.addSource(backupSource{target: prefix + "/" + file.Name, file: file, generated: cut.Current}); err != nil {
		return err
	}
	p.manifest.Entries = append(p.manifest.Entries, entry)
	if len(p.sources) > backupFileLimit {
		return store.ErrHistoryBudget
	}
	return nil
}
func (p *backupPlan) addControl(ctx context.Context, root, kind string, id domain.ID, log *store.ControlLog, clock func() time.Time) error {
	cut, e := log.BackupCapture(ctx)
	if e != nil {
		return e
	}
	if e = p.addCapture(controlOwnerPath(root, kind, id), kind, id, "control", cut, clock()); e != nil {
		return e
	}
	p.manifest.ControlCut = append(p.manifest.ControlCut, backupCut{kind, id, cut.Sequence})
	return nil
}
func (p *backupPlan) addPosting(ctx context.Context, b *postingBoard, clock func() time.Time) error {
	if b == nil || b.stopped {
		return ErrPostingUnavailable
	}
	keys := make([]uint64, 0, len(b.threads))
	for key := range b.threads {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if b.threads[key].Reclaimed() {
			continue
		}
		cut, e := b.threads[key].BackupCapture(ctx)
		if e != nil {
			return e
		}
		if cut.Expires <= domain.Time(clock().UnixNano()) {
			return fmt.Errorf("expired thread requires cleanup before backup: %s/%d", b.owner, key)
		}
		if e = p.addCapture(filepath.Join(b.threadsDir, fmt.Sprint(key)), "thread", b.owner, fmt.Sprint(key), cut, clock()); e != nil {
			return e
		}
	}
	days, e := postingNames(b.evidenceDir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	for _, day := range days {
		journal := b.journals[day]
		if journal == nil {
			return ErrPostingUnavailable
		}
		cut, e := journal.BackupCapture(ctx)
		if e != nil {
			return e
		}
		if e = p.addCapture(filepath.Join(b.evidenceDir, fmt.Sprint(day)), "evidence", b.owner, fmt.Sprint(day), cut, clock()); e != nil {
			return e
		}
	}
	return nil
}

func (p *backupPlan) addAudit(ctx context.Context, root string, clock func() time.Time) error {
	owners, e := childIDs(filepath.Join(root, "audit"))
	if e != nil {
		return e
	}
	for _, id := range owners {
		kind := "board"
		if id == p.manifest.Site {
			kind = "site"
		}
		names, e := boundedAuditNames(filepath.Join(root, "audit", id.String()), 10000)
		if e != nil {
			return e
		}
		for _, day := range names {
			subkey, e := strconv.ParseUint(day, 10, 64)
			if e != nil {
				return e
			}
			dir := filepath.Join(root, "audit", id.String(), day)
			log, e := store.OpenControl(dir, 4, id, subkey, auditValueValidator(id, kind, day))
			if e != nil {
				return e
			}
			cut, err := log.BackupCapture(ctx)
			if err == nil {
				for name, row := range log.State().Rows {
					if strings.HasPrefix(name, "audit_entry:") && row.Expires != nil {
						if cut.Expires == 0 {
							cut.Expires = *row.Expires
						} else {
							cut.Expires = min(cut.Expires, *row.Expires)
						}
					}
				}
			}
			closeErr := log.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if e = p.addCapture(dir, "audit", id, day, cut, clock()); e != nil {
				return e
			}
		}
	}
	return nil
}

func (p *backupPlan) addMetadata(ctx context.Context, root string, clock func() time.Time) error {
	entry := backupEntry{Kind: "metadata", Owner: p.manifest.Site, Subkey: "bootstrap", Captured: domain.Time(clock().UnixNano()), Files: []backupFile{}}
	paths := []string{"instance.json"}

	for _, cut := range p.manifest.ControlCut {
		dir := controlOwnerPath(root, cut.Kind, cut.Owner)
		m, e := store.InspectControlManifest(dir)
		if e != nil {
			return e
		}
		if m.Snapshot != nil {
			rel, e := filepath.Rel(root, filepath.Join(dir, fmt.Sprintf("control-%06d.anchor.json", m.Generation)))
			if e != nil {
				return e
			}
			paths = append(paths, filepath.ToSlash(rel))
		}
	}
	slices.Sort(paths)
	for _, name := range paths {
		if !safeBackupName(name) {
			return store.ErrCorrupt
		}
		f, e := store.HashBackupFile(ctx, filepath.Join(root, filepath.FromSlash(name)))
		if e != nil {
			return e
		}
		file := backupFile{name, f.Length, f.SHA}
		entry.Files = append(entry.Files, file)
		if err := p.addSource(backupSource{source: filepath.Join(root, filepath.FromSlash(name)), target: backupEntryPath(entry) + "/" + name, file: file}); err != nil {
			return err
		}
	}
	if e := p.addRequiredOmission(root, &entry); e != nil {
		return e
	}
	if e := p.addOptionalOmission(root, &entry); e != nil {
		return e
	}
	p.manifest.Entries = append(p.manifest.Entries, entry)
	return nil
}

// addSource は全体のbyte数とファイル数を単調に計上し、有界な計画だけを保持する。
func (p *backupPlan) addSource(source backupSource) error {
	if len(p.sources) >= backupFileLimit || uint64(source.file.Length) > backupByteLimit-p.bytes {
		return store.ErrHistoryBudget
	}
	p.bytes += uint64(source.file.Length)
	p.sources = append(p.sources, source)
	return nil
}

// addJobs は保持期限内の完了jobだけを捕捉し、期限切れの管理入力を複製しない。
func (p *backupPlan) addJobs(ctx context.Context, root string, clock func() time.Time) error {
	ids, e := childIDs(filepath.Join(root, "jobs"))
	if e != nil {
		return e
	}
	for _, id := range ids {
		job, e := inspectJob(root, id)
		if e != nil {
			return e
		}
		if job.Expires == nil {
			return store.ErrIncomplete
		}
		if *job.Expires <= domain.Time(clock().UnixNano()) {
			continue
		}
		dir := filepath.Join(root, "jobs", id.String())
		log, e := store.OpenControl(dir, 6, id, 0, validateProvisionJob)
		if e != nil {
			return e
		}
		cut, err := log.BackupCapture(ctx)
		closeErr := log.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		cut.Expires = *job.Expires
		if e = p.addCapture(dir, "job", id, "control", cut, clock()); e != nil {
			return e
		}
	}
	return nil
}

// addDeletions は停止中に検証済みの削除正本も候補へ含める。
func (p *backupPlan) addDeletions(ctx context.Context, b *postingBoard, clock func() time.Time) error {
	if b == nil {
		return nil
	}
	keys := make([]uint64, 0, len(b.deletions))
	for key := range b.deletions {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		cut, e := b.deletions[key].BackupCapture(ctx)
		if e != nil {
			return e
		}
		if e = p.addCapture(filepath.Join(b.root, "expiry", b.owner.String(), fmt.Sprint(key)), "deletion", b.owner, fmt.Sprint(key), cut, clock()); e != nil {
			return e
		}
	}
	return nil
}
