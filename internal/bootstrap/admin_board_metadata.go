// サイト管理者による板名・キー変更を、別名予約・CAS・再送記録と一括で耐久保存する。
package bootstrap

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type adminBoardMetadata struct {
	ID              domain.ID
	Key, Name, ETag string
	Aliases         []string
}

// boardMetadataLocked は板設定とは独立したdirectoryの版を返す。site mutex必須。
func (r *Repository) boardMetadataLocked(id domain.ID) (adminBoardMetadata, error) {
	dirs, err := siteDirectories(r.site.State())
	if err != nil {
		return adminBoardMetadata{}, err
	}
	d := dirs[id]
	b := r.posting[id]
	if d == nil || d.Status != "active" || b == nil {
		return adminBoardMetadata{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	return adminBoardMetadata{ID: id, Key: d.Key, Name: b.boardName(), Aliases: slices.Clone(d.Aliases), ETag: fmt.Sprintf(`"board-metadata:%s:%d"`, id, r.site.State().Rows["board_directory:"+id.String()].Revision)}, nil
}

// updateBoardMetadata は作成job・投稿・板設定を変更せず、単一のサイト制御操作を確定する。
func (r *Repository) updateBoardMetadata(ctx context.Context, s adminauth.Session, id domain.ID, fields url.Values) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return err
	}
	if err := r.authorizeAccountChange(s); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key, name, etag, requestID := fields.Get("key"), fields.Get("name"), fields.Get("revision"), fields.Get("request_id")
	if !validBoardKey(key) || !validName(name) {
		return &adminFailure{status: 422, code: "INVALID_BOARD_METADATA"}
	}
	if !adminRequestKey.MatchString(requestID) {
		return &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return err
	}
	defer clear(secret[:])
	requestKey := identity.MAC(secret[:], "oimo/admin-key/v1", s.Admin[:], []byte(requestID))
	request := identity.MAC(secret[:], "oimo/board-metadata/v1", s.Admin[:], id[:], []byte(key), []byte(name), []byte(etag))
	state := r.site.State()
	now := domain.Time(time.Now().UnixNano())
	if prior, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var receipt adminReceipt
		if err := strictjson.Decode(prior.Value, &receipt); err != nil {
			return err
		}
		if receipt.Created > now {
			return ErrPostingUnavailable
		}
		if receipt.Expires > now {
			if receipt.Request != request {
				return &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			return nil
		}
	}
	view, err := r.boardMetadataLocked(id)
	if err != nil {
		return err
	}
	if view.ETag != etag {
		return &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	dirs, err := siteDirectories(state)
	if err != nil {
		return err
	}
	for owner, d := range dirs {
		if owner != id && d.matchesKey(key) {
			return &adminFailure{status: 409, code: "BOARD_KEY_EXISTS"}
		}
	}
	d := *dirs[id]
	if d.Key != key {
		aliases := append(slices.Clone(d.Aliases), d.Key)
		d.Aliases = slices.DeleteFunc(aliases, func(alias string) bool { return alias == key })
		slices.Sort(d.Aliases)
		d.Key = key
	}
	d.Name = name
	if d.validateMetadata() != nil {
		return &adminFailure{status: 422, code: "BOARD_ALIAS_LIMIT"}
	}
	var refreshedReceipt *app.PostingSnapshot
	if r.cfg.AutoReports != nil {
		refreshedReceipt, err = receiptSnapshotForBoard(r.cfg.Public.BaseURL, d.Key, r.operations().Reports, r.posting[id].autoReports.Load())
		if err != nil {
			return err
		}
	}
	count := 0
	for key := range state.Rows {
		if strings.HasPrefix(key, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) || now > domain.Time(1<<63-1)-86400e9 {
		return ErrPostingUnavailable
	}
	var site siteState
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return err
	}
	seq := state.Seq + 1
	site.MinimumReader = max(site.MinimumReader, boardMetadataReader)
	site.PublicRevision = seq
	opID := domain.NewID()
	receipt := adminReceipt{ID: opID, Admin: s.Admin, Key: requestKey, Request: request, Name: name, Revision: seq, Created: now, Expires: now + 86400e9}
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("board_directory", id.String(), d, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
	actorKey := uint32(8)
	actor := domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "board_metadata_update", Request: &request, Idempotency: &requestKey, KeyID: &actorKey}
	frame, err := controlFrame(state, opID, now, "board_metadata_update", changes, []string{id.String()}, actor)
	if err != nil {
		return err
	}
	r.checkpoint("board_metadata_prepared")
	if r.site.Append(frame).Status != store.Durable {
		r.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: opID}
	}
	r.checkpoint("board_metadata_durable")
	r.posting[id].publishMetadata(d)
	if refreshedReceipt != nil {
		r.posting[id].receipt.Store(refreshedReceipt)
	}
	r.publicRevision.Store(uint64(seq))
	r.checkpoint("board_metadata_saved")
	return nil
}
