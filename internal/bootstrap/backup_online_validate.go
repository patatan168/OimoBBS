// コピー側の所有者・監査境界・投稿証拠を再生照合し、正本の状態を補修しない。
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
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func (r *Repository) validateOnlineSiteCopy(ctx context.Context, root string, v onlineSiteBoundary, cut OnlineBackupGroupCapture) (err error) {
	view := &Repository{cfg: Config{DataDir: root}, anchors: v.anchors}
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	archiveBudget := int64(64 << 20)
	controls := map[domain.ID]*store.ControlLog{}
	defer func() {
		for _, log := range controls {
			err = errors.Join(err, log.Close())
		}
	}()
	for _, c := range cut.Captures {
		if e := ctx.Err(); e != nil {
			return e
		}
		if c.Kind != "site" && c.Kind != "board" {
			continue
		}
		kind := uint16(2)
		validator, snapshot := validateBoardValue, snapshotBoardValue
		if c.Kind == "site" {
			kind = 1
			validator, snapshot = validateSiteValue, snapshotSiteValue
		}
		path := filepath.Join(root, c.Kind, c.Owner.String(), c.Subkey)
		log, e := store.OpenControlWithValidators(path, kind, c.Owner, 0, validator, snapshot)
		if e != nil {
			return e
		}
		controls[c.Owner] = log
		if log.State().Seq != c.Capture.Sequence {
			return store.ErrCorrupt
		}
		report, e := view.verifyAuditOwner(ctx, c.Owner, c.Kind, log, &budget, &archiveBudget)
		if e != nil {
			return e
		}
		if !report.Complete {
			return errors.New("audit transfer incomplete at online boundary")
		}
	}
	site := controls[v.state.ID]
	if site == nil {
		return store.ErrCorrupt
	}
	dirs, e := siteDirectories(site.State())
	if e != nil {
		return e
	}
	if len(dirs) != len(v.boards) || len(controls) != len(dirs)+1 {
		return store.ErrCorrupt
	}
	for _, b := range v.boards {
		if dirs[b.owner] == nil || controls[b.owner] == nil {
			return store.ErrCorrupt
		}
		if e := validateOnlineBoardCopy(ctx, root, v.validation[b.owner], controls[b.owner], cut.Captures); e != nil {
			return e
		}
	}
	for _, c := range cut.Captures {
		if c.Kind != "job" {
			continue
		}
		state, e := store.InspectControl(filepath.Join(root, c.Kind, c.Owner.String(), c.Subkey), 6, c.Owner, 0, validateProvisionJob)
		if e != nil {
			return e
		}
		var job provisionJob
		if e = strictjson.Decode(state.Rows["job:"+c.Owner.String()].Value, &job); e != nil {
			return e
		}
		dir := dirs[job.Parameters.BoardID]
		if job.State != "completed" || job.Expires == nil || dir == nil || dir.JobID != job.ID || dir.Key != job.Parameters.Key || *job.Expires != c.Capture.Expires {
			return store.ErrCorrupt
		}
	}
	return nil
}

func validateOnlineBoardCopy(ctx context.Context, root string, b *postingBoard, control *store.ControlLog, captures []OnlineBackupOwnerCapture) (err error) {
	journals := []*evidence.Journal{}
	defer func() {
		for _, j := range journals {
			err = errors.Join(err, j.Close())
		}
	}()
	for i, c := range captures {
		if c.Owner != b.owner || c.Kind != "evidence" {
			continue
		}
		day, e := strconv.ParseUint(c.Subkey, 10, 64)
		if e != nil {
			return e
		}
		j, e := evidence.OpenJournal(filepath.Join(root, c.Kind, c.Owner.String(), c.Subkey), c.Owner, day, 10, b.key, app.PostingValidator(b.validate))
		if e != nil {
			return e
		}
		journals = append(journals, j)
		for _, entry := range j.Entries() {
			// OpenJournalで照合済みの日末境界/回収証跡は、現用個人記録の期限を持たない。
			if entry.Event.Kind == "journal_checkpoint" || entry.Event.Kind == "tombstone" {
				continue
			}
			var retention struct {
				Until domain.Time `json:"retention_until_ns"`
			}
			if e = json.Unmarshal(entry.Payload, &retention); e != nil {
				return e
			}
			if captures[i].Capture.Expires == 0 || retention.Until < captures[i].Capture.Expires {
				captures[i].Capture.Expires = retention.Until
			}
			if retention.Until <= domain.Time(time.Now().UnixNano()) {
				return errors.New("expired evidence requires maintenance before online backup")
			}
		}
	}
	var watermark struct {
		Last domain.U64 `json:"last_reserved_key"`
	}
	if e := strictjson.Decode(control.State().Rows["key_watermark:thread"].Value, &watermark); e != nil {
		return e
	}
	seen := map[uint64]bool{}
	for _, c := range captures {
		if c.Owner != b.owner || c.Kind != "thread" {
			continue
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		key, e := strconv.ParseUint(c.Subkey, 10, 64)
		if e != nil {
			return e
		}
		if key > uint64(watermark.Last) || seen[key] {
			return fmt.Errorf("online thread reservation mismatch: %d", key)
		}
		seen[key] = true
		if len(journals) == 0 {
			return errors.New("online thread has no evidence")
		}
		p, e := app.OpenPosting(filepath.Join(root, "thread", b.owner.String()), b.owner, key, journals, journals[0], domain.Time(time.Now().UnixNano()))
		if e != nil {
			return e
		}
		seq, _, stateErr := p.ModerationState()
		e = p.Close()
		if e != nil {
			return e
		}
		if stateErr != nil || seq != c.Capture.Sequence {
			return store.ErrCorrupt
		}
	}

	for _, c := range captures {
		if c.Owner != b.owner || c.Kind != "deletion" {
			continue
		}
		key, e := strconv.ParseUint(c.Subkey, 10, 64)
		if e != nil || key == 0 || key > uint64(watermark.Last) {
			return store.ErrCorrupt
		}
		state, e := inspectDeletionControl(filepath.Join(root, c.Kind, c.Owner.String(), c.Subkey), c.Owner, key)
		if e != nil {
			return e
		}
		if state.Seq != c.Capture.Sequence {
			return store.ErrCorrupt
		}
		if e = inspectCarryErasureReference(readerVersion, control.State(), state, b.owner, key); e != nil {
			return e
		}
		if len(journals) == 0 {
			return app.ErrEvidenceGap
		}
		proof, e := readBodyReclamation(state, b.owner, key, b.key.Public().(ed25519.PublicKey))
		if e != nil {
			return e
		}
		if (proof == nil) != seen[key] {
			return store.ErrCorrupt
		}
		p, e := openOnlineReclaimedPosting(root, b, control, key, journals, state, proof)
		if e != nil {
			return e
		}
		if e = validateDeletionTasks(state, key); e != nil {
			return errors.Join(e, p.Close())
		}
		for name, row := range state.Rows {
			if !strings.HasPrefix(name, "deletion:") {
				continue
			}
			var v DeletionRecord
			if e = strictjson.Decode(row.Value, &v); e != nil {
				break
			}
			if v.Board != c.Owner || v.Thread != domain.U64(key) || (v.Phase != "applied" && v.Phase != "cleaning") {
				e = store.ErrCorrupt
				break
			}
			if v.Kind == "expire" {
				seq, expires, _, ok := p.RetentionState()
				if proof == nil || !ok || seq != v.Expected || expires != v.Expires {
					e = store.ErrCorrupt
					break
				}
				continue
			}
			if v.TargetSeq == nil || !p.ModerationApplied(v.TargetOperation, *v.TargetSeq, v.ID) {
				e = store.ErrCorrupt
				break
			}
		}
		if e == nil {
			e = verifyDeletionTasks(state, p)
		}
		if e == nil {
			if row, ok := state.Rows["reclamation:audit"]; ok {
				var audit threadAuditTransfer
				if strictjson.Decode(row.Value, &audit) != nil {
					e = store.ErrCorrupt
				} else {
					view := &postingBoard{root: root, owner: b.owner, clock: time.Now}
					e = view.verifyThreadAuditDays(audit)
				}
			}
		}

		e = errors.Join(e, p.Close())
		if e != nil {
			return e
		}
	}

	return nil
}
