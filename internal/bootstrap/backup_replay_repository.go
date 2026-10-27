// 公開listenerと期限切れjobの再生成を使わず、捕捉済み所有者の復旧検証を接続する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func validReplayAnchor(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) == 2 && parts[0] == "site" {
		return validReplayAnchorName(parts[1])
	}
	if len(parts) != 4 || parts[0] != "boards" || parts[2] != "control" {
		return false
	}
	var id domain.ID
	if e := json.Unmarshal([]byte(strconv.Quote(parts[1])), &id); e != nil || id == (domain.ID{}) {
		return false
	}
	return validReplayAnchorName(parts[3])
}
func validReplayAnchorName(name string) bool {
	if !strings.HasPrefix(name, "control-") || !strings.HasSuffix(name, ".anchor.json") {
		return false
	}
	n := strings.TrimSuffix(strings.TrimPrefix(name, "control-"), ".anchor.json")
	generation, e := strconv.ParseUint(n, 10, 64)
	return e == nil && generation > 0 && fmt.Sprintf("%06d", generation) == n
}

// replayBackupRepository は捕捉時のsite・板を検証し、通常の署名/投稿/規制復旧を実行する。
// 期限切れで除外されたjobは再生成せず、捕捉されたjobだけを検証する。
func replayBackupRepository(ctx context.Context, root string, m backupManifest) (err error) {
	r := &Repository{cfg: Config{DataDir: root}, boards: map[domain.ID]*store.ControlLog{}, posting: map[domain.ID]*postingBoard{}, checkpoint: func(string) {}, captureValidator: postcapture.Validate}
	defer func() { err = errors.Join(err, r.Close()) }()
	state, err := inspectRuntimeControl(root, "site", m.Site)
	if err != nil {
		return err
	}
	_, reportsEnabled := state.Rows["report_store:active"]
	if reportsEnabled != m.DeletionReportsOmitted {
		return errors.New("backup deletion report omission declaration mismatch")
	}
	var site siteState
	if err = strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return err
	}
	if site.MinimumReader != m.MinimumReader {
		return errors.New("backup minimum reader mismatch")
	}
	enabled, e := backupOptionalEnabled(state, m.Site)
	if e != nil {
		return e
	}
	if enabled != backupOptionalDeclared(m) {
		return errors.New("backup HTTP log omission declaration mismatch")
	}
	if enabled {
		markerRaw, e := readPrivate(filepath.Join(root, "instance.json"), 4096)
		if e != nil {
			return e
		}
		var marker instance
		if strictjson.Decode(markerRaw, &marker) != nil || marker.SiteID != m.Site {
			return store.ErrCorrupt
		}
		raw, e := readPrivate(filepath.Join(root, "reports/http", backupOptionalOmissionName), backupOptionalOmissionLimit)
		if e != nil {
			return e
		}
		var at domain.Time
		for _, entry := range m.Entries {
			if entry.Kind == "metadata" {
				at = entry.Captured
			}
		}
		if e = verifyBackupOptionalPayload(raw, m, state, at, ed25519.PublicKey(marker.SigningPublic[:])); e != nil {
			return e
		}
	}
	if e = verifyReplayRequiredOmission(root, m, state); e != nil {
		return e
	}
	r.requiredHoldsOmitted = m.RequiredHoldsOmitted
	r.cfg.Public.BaseURL = site.BaseURL
	if _, err = inspectSiteState(state, m.Site, site.BaseURL); err != nil {
		return err
	}
	r.site, err = store.OpenControlWithValidators(filepath.Join(root, "site"), 1, m.Site, 0, validateSiteValue, snapshotSiteValue)
	if err != nil {
		return err
	}
	dirs, err := siteDirectories(state)
	if err != nil {
		return err
	}
	for _, entry := range m.Entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		if entry.Kind != "board" {
			continue
		}
		directory := dirs[entry.Owner]
		if directory == nil || directory.Status != "active" {
			return errors.New("backup board is not active")
		}
		if _, err = inspectRuntimeControl(root, "board", entry.Owner); err != nil {
			return err
		}
		log, e := store.OpenControlWithValidators(controlOwnerPath(root, "board", entry.Owner), 2, entry.Owner, 0, validateBoardValue, snapshotBoardValue)
		if e != nil {
			return e
		}
		r.boards[entry.Owner] = log
	}
	if len(r.boards) != len(dirs) {
		return errors.New("backup active board is missing")
	}
	if err = inspectReplayJobs(ctx, root, state, m); err != nil {
		return err
	}
	if err = inspectAudit(r.cfg, state, site.MinimumReader, false); err != nil {
		return err
	}
	if err = r.loadControlAnchors(); err != nil {
		return err
	}
	if _, err = r.administrators(); err != nil {
		return err
	}
	reg, e := loadCapRegistry(r.site.State())
	if e != nil {
		return e
	}
	r.liveCaps.Store(reg)
	if err = r.loadAdmission(); err != nil {
		return err
	}
	if err = r.loadAnonymous(); err != nil {
		return err
	}
	if err = r.loadSlipPolicy(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = r.openPostings(); err != nil {
		return err
	}
	if err = r.restoreAbuseGuard(); err != nil {
		return err
	}
	if err = r.restoreViolations(); err != nil {
		return err
	}
	if err = r.restoreAdmission(); err != nil {
		return err
	}
	for _, entry := range m.Entries {
		if entry.Kind != "thread" {
			continue
		}
		key, _ := strconv.ParseUint(entry.Subkey, 10, 64)
		posting := r.posting[entry.Owner].threads[key]
		if posting == nil {
			return errors.New("backup thread missing after replay")
		}
		cut, e := posting.BackupCapture(ctx)
		if e != nil {
			return e
		}
		if cut.Sequence != entry.Sequence {
			return errors.New("backup thread sequence changed during replay")
		}
	}
	return nil
}
func inspectReplayJobs(ctx context.Context, root string, state store.ControlState, m backupManifest) error {
	dirs, err := siteDirectories(state)
	if err != nil {
		return err
	}
	master, err := readPrivate(filepath.Join(root, "keys/master-000001.key"), 32)
	if err != nil {
		return err
	}
	defer clear(master)
	key, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return err
	}
	defer clear(key[:])
	for _, entry := range m.Entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		if entry.Kind != "job" {
			continue
		}
		job, e := inspectJob(root, entry.Owner)
		if e != nil {
			return e
		}
		dir := dirs[job.Parameters.BoardID]
		if job.State != "completed" || dir == nil || dir.JobID != job.ID || dir.Key != job.Parameters.Key || job.Request != boardRequest(key, job.Parameters.Key, job.Parameters.Name) {
			return errors.New("backup provisioning job mismatch")
		}
	}
	return nil
}
