// 運用設定のHTMLとAPIへ認証・CSRF・CASを接続する。
package bootstrap

import (
	"io"
	"mime"
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"strconv"
)

type operationsPage struct {
	State           AdminOperations
	CSRF, RequestID string
}

var operationsTemplate = webui.Template("operations")

func (h *adminHandler) operationsRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	const route = "/api/v1/operations"
	api := r.URL.Path == route
	if r.Method == "GET" {
		v, e := h.repo.adminOperations(s)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", v.ETag())
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]any{"data": v})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_ = executeAdminTemplate(w, w, operationsTemplate, operationsPage{v, s.CSRF(route), domain.NewID().String()})
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var v OperationSettings
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
		media, _, err := mime.ParseMediaType(typ)
		if e != nil || err != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
		if e != nil || strictjson.Decode(raw, &v) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		f, e := adminForm(w, r, 8<<10, "csrf", "revision", "request_id", "maintenance_enabled", "interval_seconds", "max_threads", "max_seconds", "egress_mbps", "cache_mib", "cache_workers", "window_minutes", "quorum", "stop_minutes")
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		csrf, etag, key = f.Get("csrf"), f.Get("revision"), f.Get("request_id")
		if !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		values := map[string]int{}
		for _, name := range []string{"interval_seconds", "max_threads", "max_seconds", "egress_mbps", "cache_mib", "cache_workers", "window_minutes", "quorum", "stop_minutes"} {
			n, e := strconv.Atoi(f.Get(name))
			if e != nil || n < 0 || n > 1_000_000 {
				h.fail(w, r, 422, "INVALID_OPERATIONS")
				return
			}
			values[name] = n
		}
		enabled := f.Get("maintenance_enabled")
		if enabled != "true" && enabled != "false" {
			h.fail(w, r, 422, "INVALID_OPERATIONS")
			return
		}
		v = OperationSettings{PackMaintenanceConfig{enabled == "true", values["max_seconds"], values["interval_seconds"], values["max_threads"]}, uint64(values["egress_mbps"]) * 1_000_000, uint64(values["cache_mib"]) << 20, values["cache_workers"], ReportPolicy{values["window_minutes"] * 60, values["quorum"], values["stop_minutes"] * 60}}
	}
	result, e := h.repo.updateOperations(s, v, etag, key)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	w.Header().Set("ETag", result.ETag())
	if api {
		adminJSON(w, 200, map[string]any{"data": result})
		return
	}
	http.Redirect(w, r, "/operations", 303)
}

// 以下は管理フォームの表示単位への変換。保存単位はbyte・bit/s・秒のまま保つ。
func (v OperationSettings) EgressMbps() uint64 { return v.EgressBits / 1_000_000 }
func (v OperationSettings) CacheMiB() uint64   { return v.CacheBytes >> 20 }
func (p ReportPolicy) WindowMinutes() int      { return p.WindowSeconds / 60 }
func (p ReportPolicy) StopMinutes() int        { return p.StopSeconds / 60 }
