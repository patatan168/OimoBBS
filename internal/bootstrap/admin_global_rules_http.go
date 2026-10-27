// 掲示板全体の規制を管理し、検出ログの本文からNGワード入力へ移動する。
package bootstrap

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"strconv"
	"time"
)

var globalRulesTemplate = webui.Template("global-rules")

type globalRulesPage struct {
	Listing ruleListPage
	State   AdminGlobalRules
	Fields  url.Values
	Fresh   bool
	Message string
}
type globalRuleEdit struct {
	Action    string `json:"action"`
	ID        string `json:"id"`
	Field     string `json:"field"`
	Operator  string `json:"operator"`
	Value     string `json:"value"`
	Operation string `json:"operation"`
	Mode      string `json:"mode"`
	Minutes   uint32 `json:"minutes"`
}

func (h *adminHandler) globalRulesRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	const route = "/api/v1/global-rules"
	api := r.URL.Path == route
	h.repo.mu.Lock()
	err := h.repo.authorizeAdmin(s, "site_admin", domain.ID{})
	view := h.repo.globalRulesViewLocked()
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if r.Method == "GET" {
		w.Header().Set("ETag", view.ETag())
		w.Header().Set("X-CSRF-Token", s.CSRF(route))
		word := ""
		if id := r.URL.Query().Get("event"); id != "" {
			row, findErr := h.repo.securityLog.Find(id, time.Now())
			if findErr != nil {
				h.fail(w, r, 404, "EVENT_NOT_FOUND")
				return
			}
			if row.Source != "similar" && row.Source != "global_rule" {
				h.fail(w, r, 422, "INVALID_RULE_SOURCE")
				return
			}
			runes := []rune(row.Body)
			if len(runes) > 256 {
				runes = runes[:256]
			}
			word = string(runes)
		}
		listRequest := r.Clone(r.Context())
		listURL := *r.URL
		listQuery := r.URL.Query()
		listQuery.Del("event")
		listURL.RawQuery = listQuery.Encode()
		listRequest.URL = &listURL
		filter, filterErr := readRuleListFilter(listRequest)
		if filterErr != nil {
			h.failure(w, r, filterErr)
			return
		}
		listing := ruleListPage{Action: "/global-rules", Query: filter.Query, State: filter.State}
		for _, rule := range view.Settings.Rules {
			row := globalRuleListRow(rule, s, view.ETag())
			listing.Summary.add(row.StateCode)
			if filter.matches(row) {
				listing.Rows = append(listing.Rows, row)
			}
		}
		sortRuleRows(listing.Rows)
		keys := make([]string, len(listing.Rows))
		for i, row := range listing.Rows {
			keys[i] = row.ID
		}
		window, listErr := adminListSlice(listRequest, s, view.ETag(), keys, time.Now())
		if listErr != nil {
			h.failure(w, r, listErr)
			return
		}
		listing.Matched = window.Total
		listing.Next = ruleListNext("/global-rules", window, filter)
		listing.Rows = listing.Rows[window.Start:window.End]
		if api {
			filtered := []GlobalPostingRule{}
			for _, row := range listing.Rows {
				for _, rule := range view.Settings.Rules {
					if rule.ID.String() == row.ID {
						filtered = append(filtered, rule)
						break
					}
				}
			}
			result := view
			result.Settings.Rules = filtered
			adminJSON(w, 200, listMetadata(result, window, view.ETag()))
			return
		}
		fields := url.Values{"field": {"body"}, "operator": {"contains"}, "value": {word}, "operation": {"both"}, "mode": {"reject"}, "minutes": {"0"}, "csrf": {s.CSRF(route)}, "revision": {view.ETag()}, "request_id": {domain.NewID().String()}}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		if err := executeAdminTemplate(w, w, globalRulesTemplate, globalRulesPage{Listing: listing, State: view, Fields: fields, Fresh: s.Reauthenticated(time.Now())}); err != nil {
			h.failure(w, r, err)
		}
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	edit, etag, key, err := readGlobalEdit(w, r, s, route, api)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	next := view.Settings
	next.Rules = append([]GlobalPostingRule{}, next.Rules...)
	switch edit.Action {
	case "add":
		if edit.Minutes > 525600 {
			h.fail(w, r, 422, "INVALID_RULE")
			return
		}
		now := domain.Time(time.Now().UnixNano())
		expires := domain.Time(0)
		if edit.Minutes > 0 {
			expires = now + domain.Time(edit.Minutes)*domain.Time(time.Minute)
		}
		value := edit.Value
		operator := edit.Operator
		if edit.Field == "all" {
			value = "*"
			operator = "exact"
		}
		next.Rules = append(next.Rules, GlobalPostingRule{domain.NewID(), edit.Field, operator, value, edit.Operation, edit.Mode, now, expires, true})
	case "revoke":
		found := false
		for i, rule := range next.Rules {
			if rule.ID.String() == edit.ID {
				next.Rules[i].Enabled = false
				found = true
				break
			}
		}
		if !found {
			h.fail(w, r, 404, "RULE_NOT_FOUND")
			return
		}
	default:
		h.fail(w, r, 422, "INVALID_RULE")
		return
	}
	payload, _ := json.Marshal(edit)
	result, err := h.repo.updateGlobalRules(s, next, etag, key, payload)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if api {
		w.Header().Set("ETag", result.ETag())
		adminJSON(w, 200, map[string]any{"data": result})
		return
	}
	http.Redirect(w, r, "/global-rules", 303)
}

// readGlobalEdit はHTML/APIで同じCSRF、単一ヘッダー、入力上限を適用する。
func readGlobalEdit(w http.ResponseWriter, r *http.Request, s adminauth.Session, route string, api bool) (globalRuleEdit, string, string, error) {
	var edit globalRuleEdit
	bad := &adminFailure{status: 400, code: "INVALID_FORM"}
	if !api {
		fields, err := adminForm(w, r, 8<<10, "csrf", "revision", "request_id", "action", "id", "field", "operator", "value", "operation", "mode", "minutes")
		if err != nil {
			return edit, "", "", bad
		}
		if !s.CheckCSRF(route, fields.Get("csrf")) {
			return edit, "", "", &adminFailure{status: 403, code: "CSRF_REJECTED"}
		}
		minutes := uint64(0)
		if fields.Get("action") == "add" {
			minutes, err = strconv.ParseUint(fields.Get("minutes"), 10, 32)
			if err != nil {
				return edit, "", "", bad
			}
		}
		edit = globalRuleEdit{fields.Get("action"), fields.Get("id"), fields.Get("field"), fields.Get("operator"), fields.Get("value"), fields.Get("operation"), fields.Get("mode"), uint32(minutes)}
		return edit, fields.Get("revision"), fields.Get("request_id"), nil
	}
	csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
	if err != nil || !s.CheckCSRF(route, csrf) {
		return edit, "", "", &adminFailure{status: 403, code: "CSRF_REJECTED"}
	}
	etag, _, err := singleRequestHeader(r.Header, "If-Match")
	if err != nil {
		return edit, "", "", bad
	}
	key, _, err := singleRequestHeader(r.Header, "Idempotency-Key")
	if err != nil {
		return edit, "", "", bad
	}
	content, _, err := singleRequestHeader(r.Header, "Content-Type")
	kind, _, parseErr := mime.ParseMediaType(content)
	if err != nil || parseErr != nil || kind != "application/json" {
		return edit, "", "", &adminFailure{status: 415, code: "JSON_REQUIRED"}
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if err != nil || strictjson.Decode(raw, &edit) != nil {
		return edit, "", "", bad
	}
	return edit, etag, key, nil
}
