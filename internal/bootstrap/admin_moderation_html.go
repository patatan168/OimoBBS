// 削除対象・公開への効果・掃除状態を確認し、HTMLとAPIから同じ削除intentへ接続する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
)

type moderationThreadRow struct {
	Key           uint64
	Title, Action string
	StateAction   string
	Revision      domain.U64
}
type moderationPage struct {
	Action, Board, Message string
	Query                  string
	Previous, Next         string
	Key                    uint64
	Values                 url.Values
	Threads                []moderationThreadRow
	Records                []DeletionRecord
	Tasks                  []DeletionCopyTask
	Listing, Confirm       bool
	ReadOnly               bool
	CanCleanup             bool
}

var moderationTemplate = webui.Template("moderation")

// CleanupState は旧WAL・packの進捗を表示する。公開本体だけの回収を旧保存世代の完了とみなさない。
func (p moderationPage) CleanupState(id domain.ID) string {
	for _, task := range p.Tasks {
		if task.Deletion == id && task.Kind == "base_delta" {
			return task.StateLabel()
		}
	}
	return "未完了"
}

func writeModeration(w http.ResponseWriter, status int, p moderationPage) {
	var body bytes.Buffer
	if e := executeAdminTemplate(w, &body, moderationTemplate, p); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}
func (h *adminHandler) moderationThreads(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if r.Method != "GET" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	if api {
		h.adminThreadsList(w, r, s)
		return
	}
	threadQuery, err := adminThreadQuery(r)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		h.fail(w, r, 400, "INVALID_PAGE")
		return
	}
	pageNumber := 0
	if values, legacy := query["page"]; legacy {
		if len(query) != 1 || len(values) != 1 {
			h.fail(w, r, 400, "INVALID_PAGE")
			return
		}
		pageNumber, err = strconv.Atoi(values[0])
		if err != nil || pageNumber < 1 || pageNumber > 1000 || strconv.Itoa(pageNumber) != values[0] {
			h.fail(w, r, 400, "INVALID_PAGE")
			return
		}
	}

	prefix := "/boards/"
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	var owner domain.ID
	if len(parts) != 2 || parts[1] != "threads" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &owner) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	b, e := h.repo.postingOwner(owner)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	value, e := b.worker.Submit(r.Context(), func() (any, error) {
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		rows := []moderationThreadRow{}
		for key, p := range b.threads {
			if _, _, _, ok := p.RetentionState(); !ok {
				continue
			}
			title := "非公開スレッド"
			if summary := p.Summary(domain.Time(b.clock().UnixNano())); summary != nil {
				title = summary.Title
			}
			if !adminThreadMatches(title, threadQuery) {
				continue
			}
			seq, _, _, _ := p.RetentionState()
			rows = append(rows, moderationThreadRow{Revision: seq, Key: key, Title: title, Action: fmt.Sprintf("/boards/%s/threads/%d/moderation", owner, key), StateAction: fmt.Sprintf("/boards/%s/threads/%d/actions", owner, key)})
		}
		return rows, nil
	})
	if e != nil {
		h.failure(w, r, e)
		return
	}
	rows := value.([]moderationThreadRow)
	sortModerationThreads(rows)
	if pageNumber > 0 {
		h.legacyModerationPage(w, r, owner, rows, pageNumber)
		return
	}
	keys := make([]string, len(rows))
	for i, row := range rows {
		keys[i] = fmt.Sprint(row.Key)
	}
	revision, err := adminListRevision(rows)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	window, err := adminListSlice(r, s, revision, keys, time.Now())
	if err != nil {
		h.failure(w, r, err)
		return
	}
	page := moderationPage{Listing: true, Board: owner.String(), Query: threadQuery, Threads: rows[window.Start:window.End], Next: adminThreadNextLink(r.URL.Path, window, threadQuery)}
	writeModeration(w, 200, page)
}

// legacyModerationPage は既存の明示page番号を200件単位の互換経路として維持する。
func (h *adminHandler) legacyModerationPage(w http.ResponseWriter, r *http.Request, owner domain.ID, rows []moderationThreadRow, pageNumber int) {
	if pageNumber > max(1, (len(rows)+199)/200) {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	page := moderationPage{Listing: true, Board: owner.String(), Threads: rows[min((pageNumber-1)*200, len(rows)):min(pageNumber*200, len(rows))]}
	if pageNumber > 1 {
		page.Previous = fmt.Sprintf("%s?page=%d", r.URL.Path, pageNumber-1)
	}
	if pageNumber*200 < len(rows) {
		page.Next = fmt.Sprintf("%s?page=%d", r.URL.Path, pageNumber+1)
	}
	writeModeration(w, 200, page)
}

func (h *adminHandler) moderationHTML(w http.ResponseWriter, r *http.Request, s adminauth.Session, owner domain.ID, key uint64) {
	route := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", owner, key)
	page := moderationPage{Action: r.URL.Path, Board: owner.String(), Key: key}
	h.repo.mu.Lock()
	page.CanCleanup = h.repo.authorizeAdmin(s, "moderator", owner) == nil
	canReadHistory := h.repo.authorizeAdmin(s, "board_admin", owner) == nil
	h.repo.mu.Unlock()
	if r.Method == "GET" {
		b, e := h.repo.postingOwner(owner)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		value, e := b.worker.Submit(r.Context(), func() (any, error) {
			if b.stopped {
				return nil, ErrPostingUnavailable
			}
			p := b.threads[key]
			if p == nil {
				return nil, &adminFailure{status: 404, code: "THREAD_NOT_FOUND"}
			}
			seq, _, _, ok := p.RetentionState()
			if !ok {
				return nil, ErrPostingUnavailable
			}
			page.ReadOnly = p.PublicStatus(domain.Time(b.clock().UnixNano())) != 200
			page.Values = url.Values{"kind": {"redact"}, "ranges": {""}, "mode": {"aboon"}, "hide_title": {"false"}, "revision": {fmt.Sprintf(`"%s:%d:%d"`, owner, key, seq)}, "request_id": {domain.NewID().String()}, "csrf": {s.CSRF(route)}, "step": {"confirm"}}
			records, tasks := []DeletionRecord{}, []DeletionCopyTask{}
			var err error
			if canReadHistory {
				records, tasks, err = deletionHistory(b.deletions[key])
			}
			if err != nil {
				return nil, err
			}
			records, tasks, window, _, err := moderationHistoryWindow(r, s, records, tasks)
			if err != nil {
				return nil, err
			}
			page.Records, page.Tasks = records, tasks
			page.Next = adminNextLink(r.URL.Path, window)
			return nil, nil
		})
		_ = value
		if e != nil {
			h.failure(w, r, e)
			return
		}
		writeModeration(w, 200, page)
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	fields, e := adminForm(w, r, 64<<10, "kind", "ranges", "mode", "hide_title", "revision", "request_id", "csrf", "step")
	if e != nil {
		h.fail(w, r, 400, "INVALID_FORM")
		return
	}
	if !s.CheckCSRF(route, fields.Get("csrf")) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	page.Values = fields
	edit, e := parseModerationFields(fields)
	if e == nil && fields.Get("step") == "confirm" {
		page.Confirm = true
		page.Values.Set("step", "apply")
		writeModeration(w, 200, page)
		return
	}
	if e == nil && fields.Get("step") != "apply" {
		e = &adminFailure{status: 400, code: "INVALID_FORM"}
	}
	if e == nil {
		_, e = h.repo.ModerateThread(r.Context(), s, owner, key, edit, fields.Get("revision"), fields.Get("request_id"))
	}
	if e == nil {
		http.Redirect(w, r, page.Action, 303)
		return
	}
	if errors.Is(e, adminauth.ErrSession) {
		h.failure(w, r, e)
		return
	}
	status := 503
	page.Message = "結果を確認できません。同じ入力・要求IDで再送するか、操作の記録を確認してください。"
	var failure *adminFailure
	if errors.As(e, &failure) {
		status = failure.status
		if failure.operation != (domain.ID{}) {
			w.Header().Set("X-Operation-ID", failure.operation.String())
		}
	}
	switch status {
	case 400, 422:
		page.Message = "操作とレス番号を確認してください。番号は昇順、重複なしで合計256件以内です。"
	case 412:
		page.Message = "スレッドが更新されています。入力を控え、最新の状態を読み直してください。"
	case 409:
		page.Message = "要求IDが別の操作に使われています。最新の状態を読み直してください。"
	}
	page.Values.Set("step", "confirm")
	writeModeration(w, status, page)
}

// parseModerationFields はレス番号の昇順区間を保存型へ変換する。本文を取り込まない。
func parseModerationFields(v url.Values) (AdminModeration, error) {
	result := AdminModeration{Kind: v.Get("kind"), Ranges: []app.RedactionRange{}}
	invalid := &adminFailure{status: 422, code: "INVALID_MODERATION"}
	if result.Kind != "redact" && result.Kind != "hide" || v.Get("hide_title") != "true" && v.Get("hide_title") != "false" || v.Get("mode") != "aboon" && v.Get("mode") != "transparent" {
		return result, invalid
	}
	result.HideTitle = v.Get("hide_title") == "true"
	raw := strings.TrimSpace(v.Get("ranges"))
	if result.Kind == "hide" {
		if raw != "" || result.HideTitle {
			return result, invalid
		}
		return result, nil
	}
	if raw == "" {
		if !result.HideTitle {
			return result, invalid
		}
		return result, nil
	}
	last, total := uint64(0), uint64(0)
	for _, chunk := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(chunk), "-")
		if len(parts) > 2 {
			return result, invalid
		}
		first, e := strconv.ParseUint(parts[0], 10, 32)
		if e != nil || first == 0 || strconv.FormatUint(first, 10) != parts[0] {
			return result, invalid
		}
		end := first
		if len(parts) == 2 {
			end, e = strconv.ParseUint(parts[1], 10, 32)
			if e != nil || strconv.FormatUint(end, 10) != parts[1] {
				return result, invalid
			}
		}
		if first <= last || end < first || end-first >= 256 {
			return result, invalid
		}
		total += end - first + 1
		if total > 256 {
			return result, invalid
		}
		last = end
		result.Ranges = append(result.Ranges, app.RedactionRange{First: uint32(first), Last: uint32(end), Mode: v.Get("mode")})
	}
	return result, nil
}

// sortModerationThreads はmapの列挙順を画面へ持ち込まず、新しいキーを先に表示する。
func sortModerationThreads(rows []moderationThreadRow) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key > rows[j].Key })
}

// ViewAction は公開レスを管理人用の操作付き画面で開く。
func (r moderationThreadRow) ViewAction() string {
	return strings.TrimSuffix(r.Action, "/moderation") + "/posts/1"
}
