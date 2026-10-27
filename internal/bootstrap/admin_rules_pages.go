// 規制の登録・期限・解除を表示する管理画面。作成/解除のCSRFを経路ごとに分離する。
package bootstrap

import (
	"bytes"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
	"time"
)

type adminRuleRow struct {
	Rule                                 AdminRule
	State, CSRF, RequestID, ExpiresLabel string
}
type adminRulesPage struct {
	Name, Action, Message, RetryAction string
	SettingsAction, ThreadsAction      string
	Next                               string
	Fields, RetryFields                url.Values
	Rows                               []adminRuleRow
	QuickSubject                       bool
	MatchingRows                       []adminRuleRow
	MatchingTotal                      int
	PermanentMinutes                   uint32
	PostReturn, PostNumber             string
	Conditions                         []ruleFieldOption
	Listing                            ruleListPage
}

// rulesPage は既存規制の一覧と入力欄を描画し、レスからの選択時は投稿者規制の簡易操作を先に表示する。
func (h *adminHandler) rulesPage(w http.ResponseWriter, status int, list AdminRules, s adminauth.Session, fields url.Values, message, retryAction string, retryFields url.Values, pagination ...ruleListOptions) {
	action := "/boards/" + list.Board.String() + "/rules"
	route := "/api/v1" + action
	if fields == nil {
		fields = url.Values{"target": {""}, "field": {"auto"}, "operator": {"exact"}, "effect": {"deny"}, "operation": {"both"}, "duration_minutes": {"60"}, "reason_code": {"manual"}, "revision": {list.ETag()}, "request_id": {domain.NewID().String()}, "csrf": {s.CSRF(route)}, "extra_field": {"none"}, "extra_operator": {"exact"}, "extra_value": {""}, "allow_rule_ids": {""}}
	}
	page := adminRulesPage{ThreadsAction: "/boards/" + list.Board.String() + "/threads", SettingsAction: "/boards/" + list.Board.String() + "/settings", Conditions: ruleFieldOptions, Name: list.Name, Action: action, Message: message, Fields: fields, RetryAction: retryAction, RetryFields: retryFields}
	page.QuickSubject = fields.Get("_post_return") != "" && fields.Get("field") == "token" && fields.Get("operator") == "exact" && fields.Get("effect") == "deny" && len(fields.Get("target")) == 64 && (fields.Get("extra_field") == "none" || fields.Get("extra_field") == "")
	page.PostReturn = fields.Get("_post_return")
	page.PostNumber = fields.Get("_post_number")
	page.PermanentMinutes = permanentDenyMinutes
	now := time.Now()
	if page.QuickSubject {
		page.MatchingRows, page.MatchingTotal = matchingSubjectRules(list.Rules, fields.Get("target"), s, route, now)
	}
	if len(pagination) > 0 {
		page.Next = ruleListNext(action, pagination[0].Window, pagination[0].Filter)
		page.Listing = ruleListPage{Action: action, Query: pagination[0].Filter.Query, State: pagination[0].Filter.State, Summary: pagination[0].Summary, Matched: pagination[0].Window.Total, Next: page.Next}
	} else {
		list.Rules = list.Rules[:min(50, len(list.Rules))]
	}
	for _, rule := range list.Rules {
		row := newAdminRuleRow(rule, s, route, now)
		page.Rows = append(page.Rows, row)
		page.Listing.Rows = append(page.Listing.Rows, boardRuleListRow(row, action))
	}
	if len(pagination) == 0 {
		page.Listing.Action = action
		for _, r := range page.Listing.Rows {
			page.Listing.Summary.add(r.StateCode)
		}
		page.Listing.Matched = len(page.Listing.Rows)
	}
	var buf bytes.Buffer
	if e := executeAdminTemplate(&adminMountResponse{ResponseWriter: w, page: action}, &buf, adminRulesTemplate, page); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

var adminRulesTemplate = webui.Template("rules")

// ruleFieldOption は管理画面の条件選択肢。
type ruleFieldOption struct{ Value, Label string }

var ruleFieldOptions = []ruleFieldOption{{"auto", "IPアドレス / IPの範囲（CIDR）"}, {"host", "投稿元ホスト名"}, {"ua", "User-Agent（使用ブラウザー）"}, {"token", "匿名利用者の内部ID（主体HMAC）"}, {"line", "回線種別"}, {"name", "名前"}, {"mail", "メール"}, {"title", "タイトル"}, {"body", "本文"}, {"domain", "本文リンクのドメイン"}}

// newAdminRuleRow は保存済み規制の状態と、その規制だけに使える解除用フォーム情報を組み立てる。
func newAdminRuleRow(rule AdminRule, s adminauth.Session, route string, now time.Time) adminRuleRow {
	state := "適用中"
	expiry, _ := time.Parse(time.RFC3339Nano, rule.Expires)
	if !rule.Enabled {
		state = "解除済み"
	} else if !now.Before(expiry) && !rule.Permanent() {
		state = "期限切れ"
	}
	expiresLabel := expiry.In(domain.JST).Format("2006/01/02 15:04（日本時間）")
	if rule.Permanent() {
		expiresLabel = "永久（管理者が解除するまで）"
	}
	return adminRuleRow{Rule: rule, State: state, CSRF: s.CSRF(route + "/" + rule.ID.String() + "/revoke"), RequestID: domain.NewID().String(), ExpiresLabel: expiresLabel}
}

// matchingSubjectRules は一覧のページ位置に依存せず、同じ匿名主体だけの適用中拒否規制を最大50件表示する。
// 追加条件付きの規制は、誤って条件を広げて解除しないよう通常一覧へ残す。
func matchingSubjectRules(rules []AdminRule, target string, s adminauth.Session, route string, now time.Time) (rows []adminRuleRow, total int) {
	for _, rule := range rules {
		if rule.Match.Field != "token" || rule.Match.Operator != "exact" || rule.Match.Effect != "deny" || rule.Target != target || len(rule.Extra) != 0 {
			continue
		}
		row := newAdminRuleRow(rule, s, route, now)
		if row.State != "適用中" {
			continue
		}
		total++
		if len(rows) < 50 {
			rows = append(rows, row)
		}
	}
	return rows, total
}
