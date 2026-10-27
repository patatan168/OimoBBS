// WAFの状態表示とON/OFFを、通常フォーム/APIの同じ認可・保存処理へ接続する。
package bootstrap

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"strconv"
	"time"
)

type wafPage struct {
	State           AdminWAF
	CSRF, RequestID string
	Fresh           bool
}

var wafTemplate = webui.Template("waf")

func (h *adminHandler) wafRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	const route = "/api/v1/waf"
	api := r.URL.Path == route
	if r.Method == http.MethodGet {
		h.repo.mu.Lock()
		err := h.repo.currentAdministrator(s)
		view := h.repo.wafViewLocked()
		h.repo.mu.Unlock()
		if err != nil {
			h.failure(w, r, err)
			return
		}
		w.Header().Set("ETag", view.ETag())
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]any{"data": view})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_ = executeAdminTemplate(w, w, wafTemplate, wafPage{view, s.CSRF(route), domain.NewID().String(), s.Reauthenticated(time.Now())})
		return
	}
	if r.Method != http.MethodPost {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var value WAFSettings
	var csrf, etag, key string
	if api {
		var err error
		csrf, _, err = singleRequestHeader(r.Header, "X-CSRF-Token")
		if err != nil || !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, _, err = singleRequestHeader(r.Header, "If-Match")
		if err != nil {
			h.fail(w, r, 400, "INVALID_REVISION")
			return
		}
		key, _, err = singleRequestHeader(r.Header, "Idempotency-Key")
		if err != nil {
			h.fail(w, r, 400, "INVALID_REQUEST_KEY")
			return
		}
		typ, _, err := singleRequestHeader(r.Header, "Content-Type")
		media, _, parseErr := mime.ParseMediaType(typ)
		if err != nil || parseErr != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
		if err != nil || strictjson.Decode(raw, &value) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		var shape map[string]json.RawMessage
		_ = json.Unmarshal(raw, &shape)
		if _, present := shape["traffic"]; !present {
			value.Traffic = h.repo.wafSettings().Traffic
		} else {
			var traffic map[string]json.RawMessage
			_ = json.Unmarshal(shape["traffic"], &traffic)
			if _, present := traffic["client_enabled"]; !present {
				value.Traffic.ClientEnabled = h.repo.wafSettings().Traffic.ClientEnabled
			}
			if _, present := traffic["posting"]; !present {
				value.Traffic.Posting = h.repo.wafSettings().Traffic.Posting
			}
		}
	} else {
		fields, err := adminForm(w, r, 4<<10, "csrf", "revision", "request_id", "enabled", "traffic_enabled", "client_enabled", "client_rate", "client_burst", "global_rate", "global_burst", "client_concurrent", "global_concurrent", "search_rate", "search_burst", "search_global_rate", "search_global_burst", "search_concurrent", "posting_client_rate", "posting_client_burst", "posting_global_rate", "posting_global_burst", "posting_client_concurrent", "posting_global_concurrent")
		if err != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		csrf, etag, key = fields.Get("csrf"), fields.Get("revision"), fields.Get("request_id")
		if !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		enabled := fields.Get("enabled")
		if enabled != "true" && enabled != "false" {
			h.fail(w, r, 422, "INVALID_WAF")
			return
		}
		value.Enabled = enabled == "true"
		trafficEnabled := fields.Get("traffic_enabled")
		if trafficEnabled != "true" && trafficEnabled != "false" {
			h.fail(w, r, 422, "INVALID_WAF")
			return
		}
		value.Traffic.Enabled = trafficEnabled == "true"
		clientEnabled := fields.Get("client_enabled")
		if clientEnabled != "true" && clientEnabled != "false" {
			h.fail(w, r, 422, "INVALID_WAF")
			return
		}
		value.Traffic.ClientEnabled = clientEnabled == "true"
		inputs := []struct {
			name   string
			target *int
		}{{"client_rate", &value.Traffic.ClientRate}, {"client_burst", &value.Traffic.ClientBurst}, {"global_rate", &value.Traffic.GlobalRate}, {"global_burst", &value.Traffic.GlobalBurst}, {"client_concurrent", &value.Traffic.ClientConcurrent}, {"global_concurrent", &value.Traffic.GlobalConcurrent}, {"search_rate", &value.Traffic.SearchRate}, {"search_burst", &value.Traffic.SearchBurst}, {"search_global_rate", &value.Traffic.SearchGlobalRate}, {"search_global_burst", &value.Traffic.SearchGlobalBurst}, {"search_concurrent", &value.Traffic.SearchConcurrent}, {"posting_client_rate", &value.Traffic.Posting.ClientRate}, {"posting_client_burst", &value.Traffic.Posting.ClientBurst}, {"posting_global_rate", &value.Traffic.Posting.GlobalRate}, {"posting_global_burst", &value.Traffic.Posting.GlobalBurst}, {"posting_client_concurrent", &value.Traffic.Posting.ClientConcurrent}, {"posting_global_concurrent", &value.Traffic.Posting.GlobalConcurrent}}
		for _, input := range inputs {
			number, err := strconv.Atoi(fields.Get(input.name))
			if err != nil {
				h.fail(w, r, 422, "INVALID_WAF")
				return
			}
			*input.target = number
		}
	}
	result, err := h.repo.updateWAF(s, value, etag, key)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	w.Header().Set("ETag", result.ETag())
	if api {
		adminJSON(w, 200, map[string]any{"data": result})
		return
	}
	http.Redirect(w, r, "/waf", 303)
}
