// Cookie失効の管理画面/API。再認証・Origin・CSRFと保存結果の確認を共通経路へ接続する。
package bootstrap

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"strings"
)

type adminAnonymousPage struct {
	State   AdminAnonymous
	Fields  url.Values
	Message string
}

var anonymousTemplate = webui.Template("anonymous")

func (h *adminHandler) anonymousRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	const route = "/api/v1/anonymous"
	api := r.URL.Path == route
	if r.Method == "GET" {
		state, e := h.repo.adminAnonymous(s)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", state.ETag())
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]any{"data": state})
			return
		}
		fields := url.Values{"csrf": {s.CSRF(route)}, "request_id": {domain.NewID().String()}, "revision": {state.ETag()}, "operation": {"all"}}
		writeAdminAnonymousPage(w, 200, adminAnonymousPage{State: state, Fields: fields})
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var input anonymousAdminInput
	var htmlFields url.Values
	var key, etag, csrf string
	if api {
		var e error
		csrf, _, e = singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil || !s.CheckCSRF(route, csrf) {
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
		typ, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, params, err := mime.ParseMediaType(typ)
		if e != nil || err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
		if e != nil || strictjson.Decode(raw, &input) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		fields, e := anonymousAdminForm(w, r)
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		htmlFields = fields
		csrf, etag, key = fields.Get("csrf"), fields.Get("revision"), fields.Get("request_id")
		if !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		if fields.Get("operation") != "all" {
			h.fail(w, r, 422, "INVALID_OPERATION")
			return
		}
		if fields.Get("confirm") != "all" {
			h.fail(w, r, 422, "CONFIRMATION_REQUIRED")
			return
		}
	}
	result, e := h.repo.changeAnonymous(r.Context(), s, input, etag, key)
	if e != nil {
		if api || errors.Is(e, adminauth.ErrSession) {
			h.failure(w, r, e)
			return
		}
		status, message := 503, "結果を確認できません。同じ入力・要求IDで結果を確認してください。"
		var f *adminFailure
		if errors.As(e, &f) {
			status = f.status
			if f.operation != (domain.ID{}) {
				w.Header().Set("X-Operation-ID", f.operation.String())
			}
			switch status {
			case 403:
				message = "再認証してこの画面を読み直してください。"
			case 412:
				message = "別のCookie操作が保存されています。入力を控えてこの画面を読み直してください。"
			case 409:
				message = "要求IDが別の操作に使われています。入力を控えてこの画面を読み直してください。"
			case 400, 422:
				message = "全Cookieの失効操作を確認し、この画面を読み直してください。"
			}
		}
		h.repo.mu.Lock()
		state := h.repo.anonymousView()
		h.repo.mu.Unlock()
		writeAdminAnonymousPage(w, status, adminAnonymousPage{State: state, Fields: htmlFields, Message: message})
		return
	}
	if !api {
		http.Redirect(w, r, "/anonymous", 303)
		return
	}
	w.Header().Set("ETag", result.ETag())
	adminJSON(w, 200, map[string]any{"data": result})
}

// anonymousAdminForm は全体失効と影響確認だけのフォームを厳密に受け付ける。
func anonymousAdminForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	return adminForm(w, r, 8<<10, "csrf", "revision", "request_id", "operation", "confirm")
}

// writeAdminAnonymousPage は失敗時も同じ入力・要求IDを保持し、テンプレート検査後に応答する。
func writeAdminAnonymousPage(w http.ResponseWriter, status int, page adminAnonymousPage) {
	var buf bytes.Buffer
	if e := executeAdminTemplate(w, &buf, anonymousTemplate, page); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
