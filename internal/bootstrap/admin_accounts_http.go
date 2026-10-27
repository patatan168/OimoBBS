// 管理者の一覧・登録・更新を同じ認可と保存処理へ接続する。秘密は入力専用。
package bootstrap

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminaccess"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
)

type adminAccountsPage struct {
	ResetCSRF             string
	Boards                []boardOption
	Title                 string
	Next                  string
	Message               string
	Form                  *AdminAccount
	Rows                  []AdminAccount
	Account               *AdminAccount
	CSRF, ETag, RequestID string
}

var accountsTemplate = webui.Template("admin-accounts")

// writeAccountsPage は秘密を持たない型だけで登録・更新フォームを描画する。
func writeAccountsPage(w http.ResponseWriter, status int, page adminAccountsPage) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_ = executeAdminTemplate(w, w, accountsTemplate, page)
}

// accountsRoutes は一覧GET、登録POST、対象GET/PATCHとHTML更新POSTを限定して受け付ける。
func (h *adminHandler) accountsRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	api := strings.HasPrefix(r.URL.Path, "/api/")
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	var target domain.ID
	if path != "/administrators" {
		tail := strings.TrimPrefix(path, "/administrators/")
		if strings.Contains(tail, "/") || json.Unmarshal([]byte(strconv.Quote(tail)), &target) != nil || target == (domain.ID{}) {
			h.fail(w, r, 404, "NOT_FOUND")
			return
		}
	}
	if r.Method == "GET" {
		if !api && target == (domain.ID{}) && r.URL.RawQuery == "" && r.Context().Value(adminAssetCheckContextKey{}) == true {
			h.repo.mu.Lock()
			err := h.repo.authorizeAccountChange(s)
			h.repo.mu.Unlock()
			if err != nil {
				h.failure(w, r, err)
				return
			}
			renderAdminAssetOnly(w, r, accountsTemplate, adminAccountsPage{})
			return
		}
		rows, seq, e := h.repo.adminAccounts(s)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		page := adminAccountsPage{Title: "管理者", Rows: rows, ETag: accountListETag(seq), RequestID: domain.NewID().String(), CSRF: s.CSRF("/api/v1/administrators")}
		if target != (domain.ID{}) {
			for _, a := range rows {
				if a.ID == target {
					copy := a
					page.Account = &copy
					page.ResetCSRF = s.CSRF("/api/v1/administrators/" + target.String() + "/password-reset")
					page.Form = &copy
					page.ETag = a.ETag()
					page.CSRF = s.CSRF("/api/v1/administrators/" + target.String())
					break
				}
			}
			if page.Account == nil {
				h.fail(w, r, 404, "ACCOUNT_NOT_FOUND")
				return
			}
		}
		var window adminListWindow
		if target == (domain.ID{}) {
			keys := make([]string, len(rows))
			for i, row := range rows {
				keys[i] = row.ID.String()
			}
			var err error
			window, err = adminListSlice(r, s, page.ETag, keys, time.Now())
			if err != nil {
				h.failure(w, r, err)
				return
			}
			page.Rows = rows[window.Start:window.End]
			page.Next = adminNextLink(r.URL.Path, window)
		}
		w.Header().Set("ETag", page.ETag)
		if api {
			w.Header().Set("X-CSRF-Token", page.CSRF)
			var data any = rows
			if page.Account != nil {
				data = *page.Account
			}
			if target == (domain.ID{}) {
				adminJSON(w, 200, listMetadata(rows[window.Start:window.End], window, page.ETag))
				return
			}
			adminJSON(w, 200, map[string]any{"data": data, "request_id": page.RequestID})
			return
		}
		var selected []domain.ID
		if page.Form != nil {
			selected = page.Form.Access.Boards
		}
		page.Boards, e = h.repo.boardOptions(s, selected)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		writeAccountsPage(w, 200, page)
		return
	}
	if (target == (domain.ID{}) && r.Method != "POST") || (target != (domain.ID{}) && (api && r.Method != "PATCH" || !api && r.Method != "POST")) {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var input accountInput
	var csrf, etag, key string
	if api {
		typ, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, _, err := mime.ParseMediaType(typ)
		if e != nil || err != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		csrf, _, e = singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, _, e = singleRequestHeader(r.Header, "If-Match")
		if e != nil {
			h.fail(w, r, 400, "INVALID_REVISION")
			return
		}
		key, _, e = singleRequestHeader(r.Header, "Idempotency-Key")
		if e != nil {
			h.fail(w, r, 400, "INVALID_REQUEST_KEY")
			return
		}
		if !s.CheckCSRF("/api/v1"+path, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if e != nil || strictjson.Decode(raw, &input) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		fields, e := adminForm(w, r, 64<<10, "csrf", "revision", "request_id", "login_name", "display_name", "password", "role", "board_ids", "extra_permissions", "enabled")
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		csrf, etag, key = fields.Get("csrf"), fields.Get("revision"), fields.Get("request_id")
		input.Login, input.Display, input.Password = fields.Get("login_name"), fields.Get("display_name"), fields.Get("password")
		input.Access = AdministratorAccess{Role: fields.Get("role"), Boards: []domain.ID{}, Permissions: []string{}, Enabled: fields.Get("enabled") == "true"}
		if fields.Get("enabled") != "true" && fields.Get("enabled") != "false" {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		for _, text := range strings.Fields(fields.Get("board_ids")) {
			var id domain.ID
			if json.Unmarshal([]byte(strconv.Quote(text)), &id) != nil {
				h.fail(w, r, 422, "INVALID_BOARD")
				return
			}
			input.Access.Boards = append(input.Access.Boards, id)
		}
		input.Access.Permissions = strings.Fields(fields.Get("extra_permissions"))
		// HTMLの説明通り、サイト管理者には担当板の選択を持ち越さない。APIの厳格検査は維持する。
		if input.Access.Role == "site_admin" {
			input.Access.Boards = []domain.ID{}
		}
	}
	if !s.CheckCSRF("/api/v1"+path, csrf) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	var boards []boardOption
	if !api {
		var e error
		boards, e = h.repo.boardOptions(s, input.Access.Boards)
		if e != nil {
			h.failure(w, r, e)
			return
		}
	}
	view, e := h.repo.changeAdminAccount(s, target, input, etag, key)
	if e != nil {
		if api {
			h.failure(w, r, e)
			return
		}
		var failure *adminFailure
		if !errors.As(e, &failure) || failure.status == 403 {
			h.failure(w, r, e)
			return
		}
		if failure.operation != (domain.ID{}) {
			w.Header().Set("X-Operation-ID", failure.operation.String())
		}
		form := AdminAccount{ID: target, Login: input.Login, Display: input.Display, Access: input.Access}
		page := adminAccountsPage{Title: "管理者", Form: &form, ETag: etag, CSRF: csrf, RequestID: key, Message: "保存できませんでした。入力を確認してください。パスワードは再入力が必要です。"}
		if target != (domain.ID{}) {
			page.Account = &form
		}
		if failure.code == "INVALID_ACCESS" {
			if err := adminaccess.Validate(input.Access.Role, input.Access.Permissions); err != nil {
				page.Message = err.Error() + " パスワードは再入力が必要です。"
			}
		}
		if failure.status == 503 {
			page.Message = "保存結果を確認できません。同じ入力・要求IDで確認してください。パスワードは再入力が必要です。"
		}
		if failure.status == 412 {
			page.Message = "別の変更が保存されています。入力を控え、最新の管理者設定を開き直してください。"
		}
		if failure.status == 409 {
			page.Message = "要求IDの重複、ログイン名の重複、または最後のサイト管理者の無効化により保存できません。"
		}
		page.Boards = boards
		writeAccountsPage(w, failure.status, page)
		return
	}
	w.Header().Set("ETag", view.ETag())
	if api {
		adminJSON(w, 200, map[string]any{"data": view})
		return
	}
	// 自分自身の世代変更後は再ログインが必要。他の対象の更新は一覧へ戻る。
	landing := "/administrators"
	if view.ID == s.Admin {
		landing = "/login"
	}
	http.Redirect(w, r, landing, 303)
}
