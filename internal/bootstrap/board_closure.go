// 板の閉鎖日時を登録情報へ一度だけ保存し、公開と投稿を閉じたまま期限回収を継続する。
package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const boardClosureReader = 105

// boardClosureDeadline は通常保持期限を延長せず、閉鎖から6暦月後の最終期限を示す。
func boardClosureDeadline(at domain.Time) domain.Time {
	return domain.Time(domain.SixMonths(time.Unix(0, int64(at))).UnixNano())
}

// closePublic は板所有列で実行し、取得済み本文の送信リースも失効させる。
func (b *postingBoard) closePublic(at domain.Time) {
	b.closedAt.Store(int64(at))
	for _, p := range b.threads {
		p.BlockPublic(true)
	}
}

// closeBoard は再認証済みサイト管理者だけが実行できる。閉鎖の再送は日時を変更しない。
// 保存不確定の場合は受付を止め、再起動で登録情報から閉鎖を復旧する。
func (r *Repository) closeBoard(ctx context.Context, s adminauth.Session, id domain.ID, fields url.Values) error {
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
	view, err := r.boardMetadataLocked(id)
	if err != nil {
		return err
	}
	if fields.Get("confirm_key") != view.Key {
		return &adminFailure{status: 422, code: "BOARD_CONFIRMATION_REQUIRED"}
	}
	if !adminRequestKey.MatchString(fields.Get("request_id")) {
		return &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	dirs, err := siteDirectories(r.site.State())
	if err != nil {
		return err
	}
	if dirs[id].ClosedAt != nil {
		return nil
	}
	if fields.Get("revision") == "" {
		return &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	if fields.Get("revision") != view.ETag {
		return &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	b := r.posting[id]
	_, err = b.worker.Submit(ctx, func() (any, error) {
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		if err := r.authorizeAccountChange(s); err != nil {
			return nil, err
		}
		state := r.site.State()
		var site siteState
		if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
			return nil, err
		}
		if state.Seq == ^domain.U64(0) {
			return nil, ErrPostingUnavailable
		}
		now := domain.Time(b.clock().UnixNano())
		d := *dirs[id]
		d.ClosedAt, d.Name = &now, view.Name
		site.MinimumReader = max(site.MinimumReader, boardClosureReader)
		site.PublicRevision = state.Seq + 1
		opID := domain.NewID()
		requestKey := identity.MAC(b.dedupKey[:], "oimo/admin-key/v1", s.Admin[:], []byte(fields.Get("request_id")))
		request := identity.MAC(b.dedupKey[:], "oimo/board-close/v1", s.Admin[:], id[:], []byte(view.Key), []byte(fields.Get("revision")))
		keyID := uint32(8)
		actor := domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "board_close", Request: &request, Idempotency: &requestKey, KeyID: &keyID}
		frame, err := controlFrame(state, opID, now, "board_close", []store.Mutation{mutation("site", "state", site, nil), mutation("board_directory", id.String(), d, nil)}, []string{id.String()}, actor)
		if err != nil {
			return nil, err
		}
		r.checkpoint("board_close_prepared")
		if r.site.Append(frame).Status != store.Durable {
			r.stopped = true
			b.closePublic(now)
			return nil, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: opID}
		}
		r.checkpoint("board_close_durable")
		b.closePublic(now)
		r.boardClosureEpoch.Add(1)
		r.publicRevision.Store(uint64(site.PublicRevision))
		r.checkpoint("board_close_saved")
		b.bodyReclaimEnabled, b.carryEnabled, b.requiredRetirementEnabled, b.requiredRejectedEnabled = true, true, true, true
		if err := b.enableRetention(site.PublicRevision); err != nil {
			b.stopped = true
			return nil, err
		}
		return nil, nil
	})
	return err
}

// closedBoardWebGate は現キー・旧キーの公開取得を410で拒否する。CGI投稿は所有列でも拒否する。
func (r *Repository) closedBoardWebGate(w http.ResponseWriter, req *http.Request) bool {
	slug := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")[0]
	if strings.HasPrefix(req.URL.Path, "/test/read.cgi/") {
		slug = strings.Split(strings.TrimPrefix(req.URL.Path, "/test/read.cgi/"), "/")[0]
	} else if req.URL.Path == "/web/post" {
		slug = req.URL.Query().Get("bbs")
	}
	r.mu.RLock()
	closed := false
	for _, b := range r.posting {
		if b.matchesKey(slug) {
			closed = b.closedAt.Load() != 0
			break
		}
	}
	r.mu.RUnlock()
	if closed {
		w.Header().Set("Cache-Control", "no-store")
		threadError(w, req, 410, "この板は閉鎖されました。")
	}
	return closed
}

// boardClosure は閉鎖の確認画面と更新を同じ認可・CSRF・版照合へ接続する。
func (h *adminHandler) boardClosure(w http.ResponseWriter, req *http.Request, s adminauth.Session) {
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/boards/"), "/")
	var id domain.ID
	if len(parts) != 2 || parts[1] != "close" || id.UnmarshalJSON([]byte(`"`+parts[0]+`"`)) != nil {
		h.fail(w, req, 404, "NOT_FOUND")
		return
	}
	if req.Method != "GET" && req.Method != "POST" {
		h.fail(w, req, 405, "METHOD_NOT_ALLOWED")
		return
	}
	h.repo.mu.Lock()
	view, err := h.repo.boardMetadataLocked(id)
	var closedAt *domain.Time
	if err == nil {
		if at := h.repo.posting[id].closedAt.Load(); at != 0 {
			value := domain.Time(at)
			closedAt = &value
		}
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, req, err)
		return
	}
	fields := url.Values{"csrf": {s.CSRF(req.URL.Path)}, "revision": {view.ETag}, "request_id": {domain.NewID().String()}}
	status, message := 200, ""
	if req.Method == "POST" {
		fields, err = adminForm(w, req, 8192, "csrf", "confirm_key", "revision", "request_id")
		if err != nil {
			h.fail(w, req, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF(req.URL.Path, fields.Get("csrf")) {
			h.fail(w, req, 403, "CSRF_REJECTED")
			return
		}
		err = h.repo.closeBoard(req.Context(), s, id, fields)
		if err == nil {
			http.Redirect(w, req, req.URL.Path, 303)
			return
		}
		var f *adminFailure
		if !errors.As(err, &f) || f.status != 422 {
			h.failure(w, req, err)
			return
		}
		status, message = 422, "確認のため、この板の板キーを入力してください。"
	}
	writeAdminBoards(w, status, adminBoardsPage{Closing: true, ClosedAt: closedAt, BoardKey: view.Key, Name: view.Name, Action: req.URL.Path, Values: fields, CreateReady: s.Reauthenticated(time.Now()), Message: message})
}
