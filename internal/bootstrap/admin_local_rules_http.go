// ローカルルールを管理APIとHTMLから同じ保存処理へ接続する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"strconv"
	"strings"
)

// localRules は認証後の設定表示・保存を扱い、HTMLエラーでは入力を保持する。
func (h *adminHandler) localRules(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	prefix := "/boards/"
	if api {
		prefix = "/api/v1/boards/"
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	var id domain.ID
	if len(parts) != 2 || parts[1] != "local-rules" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &id) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	route := "/api/v1/boards/" + id.String() + "/local-rules"
	action := "/boards/" + id.String() + "/local-rules"
	if r.Method == "GET" {
		b, e := h.repo.adminLocalRules(r.Context(), s, id, nil, "", "")
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", b.ETag())
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]any{"data": b, "revision": b.Revision, "request_id": domain.NewID()})
		} else {
			fields := localRuleFields(b.Settings)
			fields.Set("revision", b.ETag())
			fields.Set("request_id", domain.NewID().String())
			fields.Set("csrf", s.CSRF(route))
			writeLocalRules(w, 200, localRulesPage{Action: action, Values: fields})
		}
		return
	}
	if api && r.Method != "PATCH" || !api && r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var edit LocalRules
	var fields url.Values
	var etag, key string
	var e error
	if api {
		csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
		if err != nil || !s.CheckCSRF(route, csrf) {
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
		content, _, err := singleRequestHeader(r.Header, "Content-Type")
		media, params, err2 := mime.ParseMediaType(content)
		if err != nil || err2 != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
		if err != nil {
			h.fail(w, r, 413, "BODY_TOO_LARGE")
			return
		}
		if strictjson.Decode(raw, &edit) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		fields, e = adminForm(w, r, 256<<10, localRuleFieldNames...)
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF(route, fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, key = fields.Get("revision"), fields.Get("request_id")
		edit, e = parseLocalRuleFields(fields)
	}
	var result AdminLocalRules
	if e == nil {
		result, e = h.repo.adminLocalRules(r.Context(), s, id, &edit, etag, key)
	}
	if e != nil {
		if api || errors.Is(e, adminauth.ErrSession) {
			h.failure(w, r, e)
			return
		}
		status, message := 503, "結果を確認できません。同じ入力・要求IDで確認してください。"
		var f *adminFailure
		if errors.As(e, &f) {
			status = f.status
			if f.operation != (domain.ID{}) {
				w.Header().Set("X-Operation-ID", f.operation.String())
			}
		}
		switch status {
		case 400, 422:
			message = "ローカルルールは128項目・合計16KiB以内、1項目2048バイト以内にしてください。リンクはhttpまたはhttpsのURLを指定してください。"
		case 412:
			message = "別の変更が保存されています。入力内容を控え、最新の設定を読み直してください。"
		case 409:
			message = "要求IDが別の変更に使われています。最新の設定を読み直してください。"
		}
		writeLocalRules(w, status, localRulesPage{Action: action, Values: fields, Message: message})
		return
	}
	if !api {
		http.Redirect(w, r, action, 303)
		return
	}
	w.Header().Set("ETag", result.ETag())
	adminJSON(w, 200, map[string]any{"data": result, "revision": result.Revision, "request_id": domain.NewID()})
}

var localRuleFieldNames = []string{"text", "revision", "request_id", "csrf"}

// localRuleFields は構造化設定を編集可能なテキストへ戻す。
func localRuleFields(v LocalRules) url.Values { return url.Values{"text": {localRulesText(v.Rules)}} }

// parseLocalRuleFields は一行ごとのルールを構造化して検査する。
func parseLocalRuleFields(v url.Values) (LocalRules, error) {
	rules, e := parseLocalRulesText(v.Get("text"))
	if e != nil {
		e = &adminFailure{status: 422, code: "INVALID_SETTINGS"}
	}
	return LocalRules{Rules: rules}, e
}
