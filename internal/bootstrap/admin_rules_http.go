// 板規制の一覧・登録・解除を管理専用HTTPへ公開する。対象IPを公開投稿応答へ出さない。
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
	"sort"
	"strconv"
	"strings"
	"time"
)

func (h *adminHandler) ruleRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	prefix := "/boards/"
	if api {
		prefix = "/api/v1/boards/"
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	var board, rule domain.ID
	if len(parts) != 2 && len(parts) != 4 || parts[1] != "rules" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &board) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	if len(parts) == 4 && (parts[3] != "revoke" || json.Unmarshal([]byte(strconv.Quote(parts[2])), &rule) != nil) {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	route := "/api/v1/boards/" + board.String() + "/rules"
	action := "/boards/" + board.String() + "/rules"
	if rule != (domain.ID{}) {
		route += "/" + rule.String() + "/revoke"
	}
	if r.Method == "GET" && rule == (domain.ID{}) {
		list, e := h.repo.adminRulesView(r.Context(), s, board, !(r.Context().Value(adminAssetCheckContextKey{}) == true && r.URL.RawQuery == ""))
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", list.ETag())
		filter, err := readRuleListFilter(r)
		if err != nil {
			h.failure(w, r, err)
			return
		}
		summary := ruleListSummary{}
		matched := []AdminRule{}
		for _, rule := range list.Rules {
			row := boardRuleListRow(newAdminRuleRow(rule, s, route, time.Now()), action)
			summary.add(row.StateCode)
			if filter.matches(row) {
				matched = append(matched, rule)
			}
		}
		if !api {
			sort.SliceStable(matched, func(i, j int) bool {
				a, b := newAdminRuleRow(matched[i], s, route, time.Now()), newAdminRuleRow(matched[j], s, route, time.Now())
				if a.State != b.State {
					rank := map[string]int{"適用中": 0, "期限切れ": 1, "解除済み": 2}
					return rank[a.State] < rank[b.State]
				}
				return a.Rule.Starts > b.Rule.Starts
			})
		}
		list.Rules = matched
		keys := make([]string, len(list.Rules))
		for i, row := range list.Rules {
			keys[i] = row.ID.String()
		}
		window, err := adminListSlice(r, s, list.ETag(), keys, time.Now())
		if err != nil {
			h.failure(w, r, err)
			return
		}
		list.Rules = list.Rules[window.Start:window.End]
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			for i := range list.Rules {
				list.Rules[i].RevokeCSRF = s.CSRF(route + "/" + list.Rules[i].ID.String() + "/revoke")
			}

			body := listMetadata(list, window, list.ETag())
			body["revision"] = list.Revision
			adminJSON(w, 200, body)
			return
		}
		h.rulesPage(w, 200, list, s, nil, "", "", nil, ruleListOptions{window, filter, summary})
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	input, fields, etag, key, e := readRuleRequest(w, r, s, route, api, rule != (domain.ID{}))
	if e != nil {
		h.failure(w, r, e)
		return
	}
	result, e := h.repo.changeRule(r.Context(), s, board, rule, input, etag, key)
	if e == nil {
		if !api {
			http.Redirect(w, r, action, 303)
			return
		}
		result.RevokeCSRF = s.CSRF("/api/v1/boards/" + board.String() + "/rules/" + result.ID.String() + "/revoke")
		w.Header().Set("ETag", result.ETag())
		adminJSON(w, 200, map[string]any{"data": result, "revision": result.Revision, "request_id": domain.NewID()})
		return
	}
	if api || errors.Is(e, adminauth.ErrSession) {
		h.failure(w, r, e)
		return
	}
	status, message := ruleError(e)
	var f *adminFailure
	if errors.As(e, &f) && f.operation != (domain.ID{}) {
		w.Header().Set("X-Operation-ID", f.operation.String())
	}
	// 保存結果不明では一覧を読み直せない場合も、同じ入力と要求IDを保持する。
	list, err := h.repo.adminRules(r.Context(), s, board)
	if err != nil {
		list = AdminRules{Board: board, Rules: []AdminRule{}}
	}
	if rule == (domain.ID{}) {
		h.rulesPage(w, status, list, s, fields, message, "", nil)
	} else {
		h.rulesPage(w, status, list, s, nil, message, r.URL.Path, fields)
	}
}
func ruleError(e error) (int, string) {
	var f *adminFailure
	if errors.As(e, &f) {
		switch f.status {
		case 400, 422:
			if f.code == "ADMISSION_NOT_ENABLED" {
				return f.status, "追加投稿枠を使うには投稿枠制限を有効にしてください。"
			}
			return f.status, "条件・照合方法・対象操作・有効期間を確認してください。Cookie必須の規制には匿名Cookie機能の有効化が必要です。"
		case 412:
			return 412, "別の変更が保存されています。入力を控えて、一覧を読み直してください。"
		case 409:
			return 409, "要求IDが別の操作に使われているか、既に解除済みです。一覧を読み直してください。"
		case 404:
			return 404, "対象の板または規制が見つかりません。"
		}
	}
	return 503, "結果を確認できません。同じ入力・要求IDで確認してください。"
}
func readRuleRequest(w http.ResponseWriter, r *http.Request, s adminauth.Session, route string, api, revoke bool) (AdminRuleInput, url.Values, string, string, error) {
	fail := func(status int, code string) (AdminRuleInput, url.Values, string, string, error) {
		return AdminRuleInput{}, nil, "", "", &adminFailure{status: status, code: code}
	}
	if !api {
		names := []string{"csrf", "revision", "request_id"}
		if !revoke {
			names = append(names, "target", "operation", "duration_minutes", "reason_code", "field", "operator", "effect")
		}
		fields, e := compositeRuleForm(w, r, names, revoke)
		if e != nil {
			return fail(400, "INVALID_FORM")
		}
		if !s.CheckCSRF(route, fields.Get("csrf")) {
			return fail(403, "CSRF_REJECTED")
		}
		input := AdminRuleInput{}
		if !revoke {
			n, err := strconv.ParseUint(fields.Get("duration_minutes"), 10, 32)
			if err == nil && strconv.FormatUint(n, 10) == fields.Get("duration_minutes") {
				input.Minutes = uint32(n)
			}
			input.Target = fields.Get("target")
			if raw := fields.Get("allow_rule_ids"); raw != "" {
				ids, e := parseAllowedRuleIDs(raw)
				if e != nil {
					return fail(422, "INVALID_ALLOWED_RULES")
				}
				input.Allowed = ids
			}
			if fields.Get("effect") == "rate_override" {
				refill, e1 := strconv.ParseUint(fields.Get("refill_seconds"), 10, 32)
				burst, e2 := strconv.ParseUint(fields.Get("burst"), 10, 32)
				window, e3 := strconv.ParseUint(fields.Get("window_limit"), 10, 32)
				if e1 != nil || e2 != nil || e3 != nil {
					return fail(422, "INVALID_RULE")
				}
				input.Rate = &AdminRateOverride{uint32(refill), uint32(burst), uint32(window)}
			} else if fields.Get("refill_seconds") != "" || fields.Get("burst") != "" || fields.Get("window_limit") != "" {
				return fail(422, "INVALID_RULE")
			}
			if fields.Get("extra_field") != "" && fields.Get("extra_field") != "none" {
				input.Extra = []AdminRuleCondition{{fields.Get("extra_field"), fields.Get("extra_operator"), fields.Get("extra_value")}}
			} else if fields.Get("extra_value") != "" {
				return fail(422, "INVALID_RULE")
			}
			m := AdminRuleMatch{fields.Get("field"), fields.Get("operator"), fields.Get("effect")}
			if m.Field == "auto" && m.Operator == "exact" {
				m.Field, m.Operator = input.match().Field, input.match().Operator
			}
			if fields.Get("field") != "auto" || fields.Get("operator") != "exact" || m.Effect != "deny" {
				input.Match = &m
			}
			input.Reason = fields.Get("reason_code")
			input.Operations = []string{fields.Get("operation")}
			if fields.Get("operation") == "both" {
				input.Operations = []string{"create", "reply"}
			}
		}
		return input, fields, fields.Get("revision"), fields.Get("request_id"), nil
	}
	csrf, _, e := singleRequestHeader(r.Header, "X-CSRF-Token")
	if e != nil || !s.CheckCSRF(route, csrf) {
		return fail(403, "CSRF_REJECTED")
	}
	etag, _, e := singleRequestHeader(r.Header, "If-Match")
	if e != nil {
		return fail(400, "INVALID_REVISION")
	}
	key, _, e := singleRequestHeader(r.Header, "Idempotency-Key")
	if e != nil {
		return fail(400, "INVALID_REQUEST_KEY")
	}
	content, _, e := singleRequestHeader(r.Header, "Content-Type")
	media, params, err := mime.ParseMediaType(content)
	if e != nil || err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		return fail(415, "JSON_REQUIRED")
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if e != nil {
		return fail(413, "BODY_TOO_LARGE")
	}
	var input AdminRuleInput
	if revoke {
		e = strictjson.Decode(raw, &struct{}{})
	} else {
		e = strictjson.Decode(raw, &input)
	}
	if e != nil {
		return fail(400, "INVALID_JSON")
	}
	return input, nil, etag, key, nil
}

// compositeRuleForm は旧フォームを維持し、追加条件の3項目を一組でだけ受け付ける。
func compositeRuleForm(w http.ResponseWriter, r *http.Request, names []string, revoke bool) (url.Values, error) {
	if revoke {
		return adminForm(w, r, 8<<10, names...)
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if e != nil {
		return nil, e
	}
	fields, e := url.ParseQuery(string(raw))
	if e != nil {
		return nil, e
	}
	for _, name := range []string{"extra_field", "extra_operator", "extra_value"} {
		if _, ok := fields[name]; ok {
			names = append(names, "extra_field", "extra_operator", "extra_value")
			break
		}
	}
	if _, ok := fields["allow_rule_ids"]; ok {
		names = append(names, "allow_rule_ids")
	}
	for _, name := range []string{"refill_seconds", "burst", "window_limit"} {
		if _, ok := fields[name]; ok {
			names = append(names, "refill_seconds", "burst", "window_limit")
			break
		}
	}
	if e := normalizeRuleNetworkChoices(fields); e != nil {
		return nil, e
	}
	r.Body = io.NopCloser(strings.NewReader(fields.Encode()))
	return adminForm(w, r, 8<<10, names...)
}
