// 保存済み板作成jobを同じ板ID・初期frameで完了させる。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// boardProvisionLookup は稼働中のWALを再走査せず、板所有者の確定済み状態で重複を確認する。
// 呼出元がsiteロックを保持し、板制御列の版は板ワーカー内で読む。
func (r *Repository) boardProvisionLookup(ctx context.Context, key string) (BoardInfo, int, error) {
	if r.captureValidator != nil {
		for id, b := range r.posting {
			if b.slug != key {
				continue
			}
			value, err := b.worker.Submit(ctx, func() (any, error) {
				return BoardInfo{ID: id, Key: b.slug, Name: b.publicName, Status: "open", Revision: b.control.State().Rows["board:state"].Revision}, nil
			})
			if err != nil {
				return BoardInfo{}, len(r.posting), err
			}
			return value.(BoardInfo), len(r.posting), nil
		}
		return BoardInfo{}, len(r.posting), nil
	}
	entries, err := inspectBoardsMode(r.cfg, r.site.State(), false, false)
	if err != nil {
		return BoardInfo{}, 0, err
	}
	for _, entry := range entries {
		if entry.info.Key == key {
			return entry.info, len(entries), nil
		}
	}
	return BoardInfo{}, len(entries), nil
}

// provisionActor は管理画面による作成の実行者と内容HMACを復旧後も保持する。
func provisionActor(job provisionJob) domain.Actor {
	if job.OwnerAdmin == nil {
		return domain.Actor{Kind: "system", Reason: "provision_board"}
	}
	kid := uint32(8)
	return domain.Actor{Kind: "admin", ID: job.OwnerAdmin, Reason: "provision_board", Request: &job.Request, Idempotency: &job.Request, KeyID: &kid}
}

func boardInitialFrame(job provisionJob) ([]byte, error) {
	value := boardValue{Name: job.Parameters.Name, Status: "open", Settings: job.Parameters.Settings}
	watermark := struct {
		Last domain.U64 `json:"last_reserved_key"`
	}{0}
	bump := struct {
		Last domain.U64 `json:"last_removed_bump"`
	}{0}
	return controlFrame(store.ControlState{}, job.ID, job.Created, "provision_board", []store.Mutation{mutation("board", "state", value, nil), mutation("key_watermark", "thread", watermark, nil), mutation("bump_watermark", "ranking", bump, nil)}, []string{job.Parameters.BoardID.String()})
}
func (r *Repository) resumeBoard(job provisionJob) (info BoardInfo, err error) {
	defer func() {
		if err != nil {
			r.stopped = true
		}
	}()
	id := job.Parameters.BoardID
	info = BoardInfo{ID: id, Key: job.Parameters.Key, Name: job.Parameters.Name}
	dirs, err := siteDirectories(r.site.State())
	if err != nil {
		return info, err
	}
	directory := dirs[id]
	if directory == nil {
		directory = &boardDirectory{Key: job.Parameters.Key, Aliases: []string{}, Status: "provisioning", JobID: job.ID}
		changes := []store.Mutation{mutation("board_directory", id.String(), directory, nil)}
		actor := provisionActor(job)
		actor.Reason = "board_provisioning"
		frame, e := controlFrame(r.site.State(), domain.NewID(), domain.Time(time.Now().UnixNano()), "board_provisioning", changes, []string{id.String()}, actor)
		if e != nil {
			return info, e
		}
		if result := r.site.Append(frame); result.Status != store.Durable {
			return info, errors.New("board provisioning commit not durable")
		}
	}
	r.checkpoint("provisioning")
	if directory.Status == "provisioning" {
		if err = r.completeBoardControl(job); err != nil {
			return info, err
		}
		r.checkpoint("board")
		if err = r.activateBoard(id, *directory); err != nil {
			return info, err
		}
	} else if r.boards[id] == nil {
		r.boards[id], err = store.OpenControl(filepath.Join(r.cfg.DataDir, "boards", id.String(), "control"), 2, id, 0, validateBoardValue)
		if err != nil {
			return info, err
		}
	}
	r.checkpoint("active")
	if job.State != "completed" {
		if err = r.finishJob(job); err != nil {
			return info, err
		}
	}
	r.checkpoint("completed")
	info.Status = "open"
	info.Revision = r.boards[id].State().Rows["board:state"].Revision
	return info, nil
}
func (r *Repository) completeBoardControl(job provisionJob) error {
	dir := filepath.Join(r.cfg.DataDir, "boards", job.Parameters.BoardID.String())
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	r.checkpoint("board_directory")
	if err := ensurePrivateDir(filepath.Join(dir, "threads")); err != nil {
		return err
	}
	frame, err := boardInitialFrame(job)
	if err != nil {
		return err
	}
	log, err := store.CompleteControlCreation(filepath.Join(dir, "control"), store.Header{Kind: 2, Owner: job.Parameters.BoardID, Generation: 1}, frame, validateBoardValue)
	if err != nil {
		return err
	}
	r.boards[job.Parameters.BoardID] = log
	if log.State().Seq != 1 {
		return errors.New("provisioned board already has mutations")
	}
	return nil
}
func ensurePrivateDir(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return makePrivateDir(path)
	} else if err != nil {
		return err
	}
	if err := privatePath(path, true); err != nil {
		return err
	}
	return store.SyncDirectory(filepath.Dir(path))
}
func (r *Repository) activateBoard(id domain.ID, directory boardDirectory) error {
	directory.Status = "active"
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	site.PublicRevision = r.site.State().Seq + 1
	if err := appendControl(r.site, "board_activated", []store.Mutation{mutation("board_directory", id.String(), directory, nil), mutation("site", "state", site, nil)}, []string{id.String()}); err != nil {
		return err
	}
	r.publicRevision.Store(uint64(site.PublicRevision))
	return nil
}
func (r *Repository) finishJob(job provisionJob) (err error) {
	log, err := store.OpenControl(filepath.Join(r.cfg.DataDir, "jobs", job.ID.String()), 6, job.ID, 0, validateProvisionJob)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, log.Close()) }()
	now := domain.Time(time.Now().UnixNano())
	if now < job.Created || int64(now) > 1<<63-1-30*86400*1e9 {
		return errors.New("job completion clock out of range")
	}
	expiry := now + domain.Time(30*86400*1e9)
	job.State = "completed"
	job.Finished = &now
	job.Expires = &expiry
	job.Cursor = 1
	job.Totals = provisionTotals{Total: 1, Succeeded: 1}
	if err = appendControl(log, "board_provisioned", []store.Mutation{mutation("job", job.ID.String(), job, &expiry)}, []string{job.Parameters.BoardID.String()}); err != nil {
		return err
	}
	return r.registerOnlineLog("job", job.ID, "control", log)
}
