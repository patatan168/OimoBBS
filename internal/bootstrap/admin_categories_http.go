// 管理HTMLから板カテゴリーを操作し、認可・CSRF・競合時の入力保持を適用する。
package bootstrap

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
)

type categoriesPage struct {
	View                     boardCategories
	CSRF, RequestID, Message string
	Values                   url.Values
}

var categoriesTemplate = webui.Template("board-categories")

// sortCategoryBoards は管理画面の板をキー順で安定表示する。
func sortCategoryBoards(boards []categoryBoard) {
	sort.Slice(boards, func(i, j int) bool { return boards[i].Key < boards[j].Key })
}

// categoriesRoutes はサイト管理者にだけ編集を提供する。既存の認証境界内で呼び出す。
func (h *adminHandler) categoriesRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	h.repo.mu.Lock()
	err := h.repo.currentAdministrator(s)
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		w.Header().Set("Allow", "GET, POST")
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	fields := url.Values{}
	status := 200
	message := ""
	if r.Method == "POST" {
		fields, err = readBoardCategoryForm(w, r)
		if err != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF("/board-categories", fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		err = h.repo.updateBoardCategories(s, fields)
		if err == nil {
			http.Redirect(w, r, "/board-categories", 303)
			return
		}
		var failure *adminFailure
		if !errors.As(err, &failure) {
			h.failure(w, r, err)
			return
		}
		status = failure.status
		message = "入力を確認してください。名前の重複や、カテゴリー・板・表示位置が不正です。"
		switch status {
		case 412:
			message = "別の変更が保存されています。入力を控えて、この画面を開き直してください。"
		case 409:
			message = "この要求IDは別の変更に使用済みです。画面を開き直してください。"
		case 503:
			message = "保存結果を確認できません。同じ入力・要求IDで確認してください。"
		}
	}
	h.repo.mu.Lock()
	view, err := h.repo.boardCategoriesLocked()
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	requestID := domain.NewID().String()
	if r.Method == "POST" {
		view.ETag = fields.Get("revision")
		requestID = fields.Get("request_id")
	}
	var body bytes.Buffer
	err = executeAdminTemplate(w, &body, categoriesTemplate, categoriesPage{View: view, CSRF: s.CSRF("/board-categories"), RequestID: requestID, Message: message, Values: fields})
	if err != nil {
		h.fail(w, r, 503, "RENDER_FAILED")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

// Assignment は保存失敗時にも板の選択値を保持する。
func (p categoriesPage) Assignment(b categoryBoard) string {
	if p.Values.Get("action") == "assign" && p.Values.Get("board") == b.Key {
		return p.Values.Get("category")
	}
	return b.Category
}

// CategoryCounts はカテゴリーごとの所属板数を一度の走査で集計する。
func (p categoriesPage) CategoryCounts() map[string]int {
	counts := make(map[string]int, len(p.View.Categories))
	for _, b := range p.View.Boards {
		counts[b.Category]++
	}
	return counts
}

// CategoryNames は一覧の現在の所属表示に使う名前を返す。
func (p categoriesPage) CategoryNames() map[string]string {
	names := map[string]string{"": "未分類"}
	for _, c := range p.View.Categories {
		names[c.ID.String()] = c.Name
	}
	return names
}

// Position は管理画面に表示する1始まりの位置を返す。
func (p categoriesPage) Position(index int) int { return index + 1 }

// readBoardCategoryForm は操作ごとの省略項目を許容し、未知・重複・クエリ入力を拒否する。
func readBoardCategoryForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	value, ok, err := singleRequestHeader(r.Header, "Content-Type")
	media, params, parseErr := mime.ParseMediaType(value)
	if err != nil || !ok || parseErr != nil || media != "application/x-www-form-urlencoded" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		return nil, ErrPostingRequest
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if err != nil {
		return nil, err
	}
	fields, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{"csrf": true, "revision": true, "request_id": true, "action": true, "category": true, "board": true, "name": true, "position": true}
	for name, values := range fields {
		if !allowed[name] || len(values) != 1 {
			return nil, ErrPostingRequest
		}
	}
	for _, name := range []string{"csrf", "revision", "request_id", "action"} {
		if !fields.Has(name) {
			return nil, ErrPostingRequest
		}
	}
	return fields, nil
}
