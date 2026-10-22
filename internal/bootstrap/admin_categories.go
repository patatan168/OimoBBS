// 板カテゴリーの編集をサイト所有列で直列化し、分類と板割当を一括保存する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type categoryBoard struct {
	ID                  domain.ID
	Key, Name, Category string
}
type boardCategories struct {
	Categories []category
	Boards     []categoryBoard
	ETag       string
}

// boardCategoriesLocked は現在の分類と公開済み板だけを返す。呼出し側がサイトmutexを所有する。
func (r *Repository) boardCategoriesLocked() (boardCategories, error) {
	row := r.site.State().Rows["site:state"]
	var site siteState
	if err := strictjson.Decode(row.Value, &site); err != nil {
		return boardCategories{}, err
	}
	dirs, err := siteDirectories(r.site.State())
	if err != nil {
		return boardCategories{}, err
	}
	view := boardCategories{Categories: append([]category{}, site.Categories...), Boards: []categoryBoard{}, ETag: fmt.Sprintf(`"%s:%d"`, site.ID, row.Revision)}
	for id, b := range r.posting {
		assigned := ""
		if d := dirs[id]; d != nil && d.CategoryID != nil {
			assigned = d.CategoryID.String()
		}
		view.Boards = append(view.Boards, categoryBoard{id, b.slug, b.publicName, assigned})
	}
	sortCategoryBoards(view.Boards)
	return view, nil
}

// updateBoardCategories は再送照会→CAS→カテゴリー編集と割当の一括Syncを行う。
func (r *Repository) updateBoardCategories(s adminauth.Session, fields url.Values) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.currentAdministrator(s); err != nil {
		return err
	}
	key, etag := fields.Get("request_id"), fields.Get("revision")
	if !adminRequestKey.MatchString(key) {
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
	requestKey := identity.MAC(secret[:], "oimo/admin-key/v1", s.Admin[:], []byte(key))
	input := url.Values{}
	for _, name := range []string{"action", "category", "board", "name", "position", "revision"} {
		input[name] = fields[name]
	}
	request := identity.MAC(secret[:], "oimo/board-categories/v1", s.Admin[:], []byte(input.Encode()))
	state := r.site.State()
	now := domain.Time(time.Now().UnixNano())
	if prior, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var receipt struct {
			Request domain.Hash `json:"request_hmac"`
			Created domain.Time `json:"created_at_ns"`
			Expires domain.Time `json:"expires_at_ns"`
		}
		if err := json.Unmarshal(prior.Value, &receipt); err != nil {
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
	view, err := r.boardCategoriesLocked()
	if err != nil {
		return err
	}
	if etag != view.ETag {
		return &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	var site siteState
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return err
	}
	dirs, err := siteDirectories(state)
	if err != nil {
		return err
	}
	if err := editBoardCategories(&site, dirs, r.posting, fields); err != nil {
		return &adminFailure{status: 422, code: "INVALID_CATEGORIES"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) {
		return ErrPostingUnavailable
	}
	seq := state.Seq + 1
	id := domain.NewID()
	site.MinimumReader = max(site.MinimumReader, 77)
	site.PublicRevision = seq
	receipt := adminReceipt{ID: id, Admin: s.Admin, Key: requestKey, Request: request, Name: "板カテゴリー", Revision: seq, Created: now, Expires: now + 86400e9}
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
	for owner, d := range dirs {
		raw, err := json.Marshal(d)
		if err != nil {
			return err
		}
		old := state.Rows["board_directory:"+owner.String()]
		if string(raw) != string(old.Value) {
			changes = append(changes, mutation("board_directory", owner.String(), d, nil))
		}
	}
	for i := range changes {
		changes[i].ExpectedRevision = state.Rows[changes[i].Collection+":"+changes[i].Key].Revision
	}
	keyID := uint32(8)
	op := store.ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: state.Seq, Committed: now, Actor: domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "board_categories_update", Request: &request, Idempotency: &requestKey, KeyID: &keyID}, Mutations: changes, Result: store.ControlResult{Code: "board_categories_updated", Targets: []string{site.ID.String()}, RequestKey: &requestKey, Request: &request, KeyID: &keyID, Expires: &receipt.Expires}}
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	frame, err := store.EncodeFrame(store.Frame{FirstSeq: uint64(seq), Records: []store.Record{{ID: id, JSON: raw}}})
	if err != nil {
		return err
	}
	if r.site.Append(frame).Status != store.Durable {
		r.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	r.publicRevision.Store(uint64(seq))
	return nil
}

// editBoardCategories は入力を検証し、削除時は板を未分類へ戻す。投稿設定は変更しない。
func editBoardCategories(site *siteState, dirs map[domain.ID]*boardDirectory, boards map[domain.ID]*postingBoard, fields url.Values) error {
	invalid := fmt.Errorf("invalid board category")
	index := -1
	for i, c := range site.Categories {
		if c.ID.String() == fields.Get("category") {
			index = i
		}
	}
	switch fields.Get("action") {
	case "add":
		name := strings.TrimSpace(fields.Get("name"))
		if !validName(name) || len(site.Categories) >= 256 {
			return invalid
		}
		site.Categories = append(site.Categories, category{ID: domain.NewID(), Name: name})
	case "rename":
		name := strings.TrimSpace(fields.Get("name"))
		if index < 0 || !validName(name) {
			return invalid
		}
		site.Categories[index].Name = name
	case "delete":
		if index < 0 {
			return invalid
		}
		id := site.Categories[index].ID
		for _, d := range dirs {
			if d.CategoryID != nil && *d.CategoryID == id {
				d.CategoryID = nil
			}
		}
		site.Categories = append(site.Categories[:index], site.Categories[index+1:]...)
	case "move":
		position, err := strconv.Atoi(fields.Get("position"))
		if index < 0 || err != nil || position < 1 || position > len(site.Categories) {
			return invalid
		}
		row := site.Categories[index]
		site.Categories = append(site.Categories[:index], site.Categories[index+1:]...)
		site.Categories = append(site.Categories, category{})
		copy(site.Categories[position:], site.Categories[position-1:])
		site.Categories[position-1] = row
	case "assign":
		var owner domain.ID
		for id, b := range boards {
			if b.slug == fields.Get("board") {
				owner = id
			}
		}
		d := dirs[owner]
		if d == nil || d.Status != "active" {
			return invalid
		}
		if fields.Get("category") == "" {
			d.CategoryID = nil
		} else {
			if index < 0 {
				return invalid
			}
			id := site.Categories[index].ID
			d.CategoryID = &id
		}
	default:
		return invalid
	}
	names := map[string]bool{}
	for i := range site.Categories {
		c := &site.Categories[i]
		if names[c.Name] {
			return invalid
		}
		names[c.Name] = true
		c.Order = uint32(i)
	}
	return nil
}
