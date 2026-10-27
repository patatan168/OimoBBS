// 板別と掲示板全体の規制を、同じ検索・状態集計・比較しやすい一覧へ整える。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
	"sort"
	"strings"
	"time"
)

type ruleListFilter struct{ Query, State string }
type ruleListSummary struct{ Total, Active, Expired, Revoked int }
type ruleListRow struct {
	ID, Field, Operator, Value, Effect, Operation, State, StateCode, Starts, Expires, Reason string
	Details                                                                                  []string
	RevokeAction, CSRF, Revision, RequestID                                                  string
	CanRevoke                                                                                bool
}
type ruleListPage struct {
	Action, Query, State, Next string
	Summary                    ruleListSummary
	Rows                       []ruleListRow
	Matched                    int
}
type ruleListOptions struct {
	Window  adminListWindow
	Filter  ruleListFilter
	Summary ruleListSummary
}

func ruleListRoute(path string) bool {
	path = strings.TrimPrefix(path, "/api/v1")
	if path == "/global-rules" {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/boards/"), "/")
	return strings.HasPrefix(path, "/boards/") && len(parts) == 2 && parts[1] == "rules"
}

// readRuleListFilter はページをまたぐ検索を行うため、単一の既知条件だけを許可する。
func readRuleListFilter(r *http.Request) (ruleListFilter, error) {
	f := ruleListFilter{}
	q, err := url.ParseQuery(r.URL.RawQuery)
	bad := &adminFailure{status: 400, code: "INVALID_LIST_QUERY"}
	if err != nil || len(r.URL.RawQuery) > 4096 {
		return f, bad
	}
	for key, values := range q {
		if len(values) != 1 {
			return f, bad
		}
		switch key {
		case "q":
			f.Query = strings.TrimSpace(values[0])
			if len(f.Query) > 512 {
				return f, bad
			}
		case "state":
			f.State = values[0]
		case "limit", "cursor":
		default:
			return f, bad
		}
	}
	if f.State != "" && f.State != "active" && f.State != "expired" && f.State != "revoked" {
		return f, bad
	}
	return f, nil
}
func (f ruleListFilter) values() url.Values {
	v := url.Values{}
	if f.Query != "" {
		v.Set("q", f.Query)
	}
	if f.State != "" {
		v.Set("state", f.State)
	}
	return v
}
func (f ruleListFilter) matches(row ruleListRow) bool {
	if f.State != "" && f.State != row.StateCode {
		return false
	}
	text := strings.Join([]string{row.ID, row.Field, row.Operator, row.Value, row.Effect, row.Operation, row.Reason, strings.Join(row.Details, " ")}, " ")
	return strings.Contains(strings.ToLower(text), strings.ToLower(f.Query))
}
func (s *ruleListSummary) add(state string) {
	s.Total++
	switch state {
	case "active":
		s.Active++
	case "expired":
		s.Expired++
	case "revoked":
		s.Revoked++
	}
}
func ruleStateCode(enabled bool, expires time.Time, permanent bool, now time.Time) string {
	if !enabled {
		return "revoked"
	}
	if !permanent && !now.Before(expires) {
		return "expired"
	}
	return "active"
}
func ruleStateLabel(code string) string {
	return map[string]string{"active": "適用中", "expired": "期限切れ", "revoked": "解除済み"}[code]
}
func ruleListNext(action string, window adminListWindow, filter ruleListFilter) string {
	if window.Next == "" {
		return ""
	}
	q := filter.values()
	q.Set("cursor", window.Next)
	return action + "?" + q.Encode() + "#registered-rules"
}
func (p ruleListPage) StateURL(state string) string {
	q := ruleListFilter{p.Query, state}.values()
	if len(q) == 0 {
		return p.Action + "#registered-rules"
	}
	return p.Action + "?" + q.Encode() + "#registered-rules"
}

func boardRuleListRow(row adminRuleRow, action string) ruleListRow {
	r := row.Rule
	expiry, _ := time.Parse(time.RFC3339Nano, r.Expires)
	starts, _ := time.Parse(time.RFC3339Nano, r.Starts)
	state := ruleStateCode(r.Enabled, expiry, r.Permanent(), time.Now())
	effect := map[string]string{"deny": "拒否", "require_token": "Cookie必須", "allow_rule_ids": "指定規制の除外", "rate_override": "追加投稿枠"}[r.Match.Effect]
	operation := []string{}
	for _, v := range r.Operations {
		if v == "create" {
			operation = append(operation, "スレ立て")
		} else {
			operation = append(operation, "返信")
		}
	}
	value := r.Target
	if r.Match.Field == "line" {
		value = webui.ChoiceLabel("rule_network", value)
	}
	out := ruleListRow{ID: r.ID.String(), Field: webui.ChoiceLabel("rule_field", r.Match.Field), Operator: webui.ChoiceLabel("rule_operator", r.Match.Operator), Value: value, Effect: effect, Operation: strings.Join(operation, "・"), State: ruleStateLabel(state), StateCode: state, Starts: starts.In(time.FixedZone("JST", 9*3600)).Format("2006-01-02 15:04"), Expires: strings.TrimSuffix(row.ExpiresLabel, "（日本時間）"), Reason: webui.ChoiceLabel("reason", r.Reason), RevokeAction: action + "/" + r.ID.String() + "/revoke", CSRF: row.CSRF, Revision: r.ETag(), RequestID: row.RequestID, CanRevoke: r.Enabled}
	for _, c := range r.Extra {
		out.Details = append(out.Details, webui.ChoiceLabel("rule_field", c.Field)+"（"+webui.ChoiceLabel("rule_operator", c.Operator)+"） "+c.Value)
	}
	for _, id := range r.Allowed {
		out.Details = append(out.Details, "除外対象："+id.String())
	}
	if r.Rate != nil {
		out.Details = append(out.Details, fmt.Sprintf("補充間隔 %d秒・連投許容量 %d・61分上限 %d", r.Rate.RefillSeconds, r.Rate.Burst, r.Rate.WindowLimit))
	}
	return out
}

func sortRuleRows(rows []ruleListRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.StateCode != b.StateCode {
			rank := map[string]int{"active": 0, "expired": 1, "revoked": 2}
			return rank[a.StateCode] < rank[b.StateCode]
		}
		if a.Starts == b.Starts {
			return a.ID < b.ID
		}
		return a.Starts > b.Starts
	})
}

// globalRuleListRow は全板規制も板別規制と同じ表示列へ変換する。
func globalRuleListRow(rule GlobalPostingRule, s adminauth.Session, revision string) ruleListRow {
	expires := time.Unix(0, int64(rule.Expires))
	state := ruleStateCode(rule.Enabled, expires, rule.Expires == 0, time.Now())
	effect := "拒否"
	if rule.Mode == "observe" {
		effect = "検出のみ"
	}
	operation := map[string]string{"both": "スレ立て・返信", "create": "スレ立て", "reply": "返信"}[rule.Operation]
	return ruleListRow{ID: rule.ID.String(), Field: rule.FieldLabel(), Operator: rule.OperatorLabel(), Value: rule.Value, Effect: effect, Operation: operation, State: ruleStateLabel(state), StateCode: state, Starts: time.Unix(0, int64(rule.Starts)).In(domain.JST).Format("2006-01-02 15:04"), Expires: rule.ExpiryLabel(), RevokeAction: "/global-rules", CSRF: s.CSRF("/api/v1/global-rules"), Revision: revision, RequestID: domain.NewID().String(), CanRevoke: rule.Enabled}
}
