// レス数上限・終了レス設定を管理APIとHTMLから同じ保存処理へ接続する。
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

// threadSettings は認証後の設定表示・保存を扱い、HTMLエラーでは入力を保持する。
func (h *adminHandler) threadSettings(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	prefix := "/boards/"
	if api {
		prefix = "/api/v1/boards/"
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	var id domain.ID
	if len(parts) != 2 || parts[1] != "thread-settings" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &id) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	route := "/api/v1/boards/" + id.String() + "/thread-settings"
	action := "/boards/" + id.String() + "/thread-settings"
	if r.Method == "GET" {
		b, e := h.repo.adminThreadSettings(r.Context(), s, id, nil, "", "")
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", b.ETag())
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]any{"data": b, "revision": b.Revision, "request_id": domain.NewID()})
		} else {
			fields := threadFields(b.Settings)
			fields.Set("revision", b.ETag())
			fields.Set("request_id", domain.NewID().String())
			fields.Set("csrf", s.CSRF(route))
			writeThreadSettings(w, 200, threadSettingsPage{Action: action, Values: fields})
		}
		return
	}
	if api && r.Method != "PATCH" || !api && r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var edit ThreadSettings
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
		fields, e = adminForm(w, r, 256<<10, threadFieldNames...)
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF(route, fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, key = fields.Get("revision"), fields.Get("request_id")
		edit, e = parseThreadFields(fields)
	}
	var result AdminThreadSettings
	if e == nil {
		result, e = h.repo.adminThreadSettings(r.Context(), s, id, &edit, etag, key)
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
			message = "上限は1〜10000、挿入する終了レスの本文は必須です。終了レスはDAT形式で1件4096バイト以内にしてください。"
		case 412:
			message = "別の変更が保存されています。入力内容を控え、最新の設定を読み直してください。"
		case 409:
			message = "要求IDが別の変更に使われています。最新の設定を読み直してください。"
		}
		writeThreadSettings(w, status, threadSettingsPage{Action: action, Values: fields, Message: message})
		return
	}
	if !api {
		http.Redirect(w, r, action, 303)
		return
	}
	w.Header().Set("ETag", result.ETag())
	adminJSON(w, 200, map[string]any{"data": result, "revision": result.Revision, "request_id": domain.NewID()})
}

var threadFieldNames = []string{"user_post_limit", "ending_1_enabled", "ending_1_name", "ending_1_mail", "ending_1_body", "ending_2_enabled", "ending_2_name", "ending_2_mail", "ending_2_body", "revision", "request_id", "csrf"}

func threadFields(s ThreadSettings) url.Values {
	v := url.Values{"user_post_limit": {strconv.FormatUint(uint64(s.PostLimit), 10)}}
	for i, p := range []EndingSettings{s.First, s.Second} {
		prefix := "ending_" + strconv.Itoa(i+1) + "_"
		v.Set(prefix+"enabled", strconv.FormatBool(p.Enabled))
		v.Set(prefix+"name", p.Name)
		v.Set(prefix+"mail", p.Mail)
		v.Set(prefix+"body", p.Body)
	}
	return v
}

// parseThreadFields は数値・真偽値を厳格に読み、フォーム由来の改行だけを統一する。
func parseThreadFields(v url.Values) (ThreadSettings, error) {
	var s ThreadSettings
	raw := v.Get("user_post_limit")
	n, e := strconv.ParseUint(raw, 10, 32)
	if e != nil || strconv.FormatUint(n, 10) != raw {
		return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
	}
	s.PostLimit = uint32(n)
	for i, p := range []*EndingSettings{&s.First, &s.Second} {
		prefix := "ending_" + strconv.Itoa(i+1) + "_"
		enabled := v.Get(prefix + "enabled")
		if enabled != "true" && enabled != "false" {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		p.Enabled = enabled == "true"
		p.Name = v.Get(prefix + "name")
		p.Mail = v.Get(prefix + "mail")
		p.Body = strings.ReplaceAll(v.Get(prefix+"body"), "\r\n", "\n")
	}
	return s, nil
}
