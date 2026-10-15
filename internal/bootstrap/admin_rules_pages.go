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
	Rule                   AdminRule
	State, CSRF, RequestID string
}
type adminRulesPage struct {
	Name, Action, Message, RetryAction string
	SettingsAction, ThreadsAction      string
	Next                               string
	Fields, RetryFields                url.Values
	Rows                               []adminRuleRow
	Conditions                         []ruleFieldOption
}

func (h *adminHandler) rulesPage(w http.ResponseWriter, status int, list AdminRules, s adminauth.Session, fields url.Values, message, retryAction string, retryFields url.Values, pagination ...adminListWindow) {
	action := "/boards/" + list.Board.String() + "/rules"
	route := "/api/v1" + action
	if fields == nil {
		fields = url.Values{"target": {""}, "field": {"auto"}, "operator": {"exact"}, "effect": {"deny"}, "operation": {"both"}, "duration_minutes": {"60"}, "reason_code": {"manual"}, "revision": {list.ETag()}, "request_id": {domain.NewID().String()}, "csrf": {s.CSRF(route)}, "extra_field": {"none"}, "extra_operator": {"exact"}, "extra_value": {""}, "allow_rule_ids": {""}}
	}
	page := adminRulesPage{ThreadsAction: "/boards/" + list.Board.String() + "/threads", SettingsAction: "/boards/" + list.Board.String() + "/settings", Conditions: ruleFieldOptions, Name: list.Name, Action: action, Message: message, Fields: fields, RetryAction: retryAction, RetryFields: retryFields}
	if len(pagination) > 0 {
		page.Next = adminNextLink(action, pagination[0])
	} else {
		list.Rules = list.Rules[:min(50, len(list.Rules))]
	}
	now := time.Now()
	for _, rule := range list.Rules {
		state := "適用中"
		expiry, _ := time.Parse(time.RFC3339Nano, rule.Expires)
		if !rule.Enabled {
			state = "解除済み"
		} else if !now.Before(expiry) && !rule.Permanent() {
			state = "期限切れ"
		}
		page.Rows = append(page.Rows, adminRuleRow{rule, state, s.CSRF(route + "/" + rule.ID.String() + "/revoke"), domain.NewID().String()})
	}
	var buf bytes.Buffer
	if e := executeAdminTemplate(w, &buf, adminRulesTemplate, page); e != nil {
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
