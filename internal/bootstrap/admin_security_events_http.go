// WAFと投稿規制の検出・拒否を、理由別集計と本文比較つきの専用一覧で表示する。
package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/securitylog"
	"oimobbs/internal/webui"
	"strconv"
	"strings"
	"time"
)

var securityEventsTemplate = webui.Template("waf-events")

type securityEventRow struct {
	securitylog.Row
	SourceLabel, ReasonLabel, NGURL, PostURL, MatchURL, AtLabel, FirstLabel string
}
type securityReasonRow struct {
	securitylog.ReasonCount
	Label, SourceLabel string
}
type securityEventsPage struct {
	View                                         securitylog.View
	Rows                                         []securityEventRow
	Reasons                                      []securityReasonRow
	Source, Result, Reason, PreviousURL, NextURL string
}

func securitySourceLabel(source string) string {
	switch source {
	case "waf":
		return "WAF"
	case "similar":
		return "類似文"
	case "flood":
		return "埋め立て・連投"
	case "global_rule":
		return "掲示板全体の規制"
	}
	return source
}
func securityReasonLabel(reason string) string {
	labels := map[string]string{"method": "許可していないHTTPメソッド", "url_size": "URLの長さ超過", "query_fields": "URLパラメーター数の超過", "path": "不正なパス・機密ファイルの探索", "url_injection": "URLへの攻撃パターン", "query_encoding": "URLパラメーターの形式不正", "host": "接続先Hostの不一致", "body_size": "要求本文サイズの超過", "traffic_limit": "アクセス頻度・同時処理の上限", "content_length": "本文サイズ宣言の不整合", "header_fields": "ヘッダー項目数の超過", "header_size": "ヘッダーサイズの超過", "user_agent_size": "User-Agentの長さ超過", "header_control": "ヘッダー内の不正な制御文字", "header_injection": "ヘッダーへの攻撃パターン"}
	if label, ok := labels[reason]; ok {
		return label
	}
	return reason
}

func (h *adminHandler) securityEventsRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if r.Method != "GET" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	h.repo.mu.Lock()
	err := h.repo.authorizeAdmin(s, "site_admin", domain.ID{})
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if renderAdminAssetOnly(w, r, securityEventsTemplate, securityEventsPage{}) {
		return
	}
	query := r.URL.Query()
	pageNumber, _ := strconv.Atoi(query.Get("page"))
	view, err := h.repo.securityLog.Filtered(time.Now(), securitylog.Filter{Source: query.Get("source"), Result: query.Get("result"), Reason: query.Get("reason"), Page: pageNumber})
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if r.URL.Path == "/api/v1/waf-events" {
		adminJSON(w, 200, map[string]any{"data": view})
		return
	}
	page := securityEventsPage{View: view, Source: query.Get("source"), Result: query.Get("result"), Reason: query.Get("reason")}
	if view.Page > 1 {
		query.Set("page", strconv.Itoa(view.Page-1))
		page.PreviousURL = "/waf-events?" + query.Encode()
	}
	if view.Page*50 < view.Groups {
		query.Set("page", strconv.Itoa(view.Page+1))
		page.NextURL = "/waf-events?" + query.Encode()
	}
	for _, c := range view.Reasons {
		page.Reasons = append(page.Reasons, securityReasonRow{c, securityReasonLabel(c.Reason), securitySourceLabel(c.Source)})
	}
	for _, row := range view.Rows {
		entry := securityEventRow{Row: row, SourceLabel: securitySourceLabel(row.Source), ReasonLabel: securityReasonLabel(row.Reason), AtLabel: row.At.In(time.FixedZone("JST", 9*3600)).Format("2006-01-02 15:04:05"), FirstLabel: row.First.In(time.FixedZone("JST", 9*3600)).Format("01-02 15:04:05")}
		if row.Body != "" && (row.Source == "similar" || row.Source == "global_rule") {
			entry.NGURL = "/global-rules?" + url.Values{"event": {row.ID}}.Encode()
		}
		entry.PostURL = h.repo.securityPostURL(row.Board, row.Thread, row.Post, row.Rejected, row.Operation)
		entry.MatchURL = h.repo.securityPostURL(row.MatchBoard, row.MatchThread, row.MatchPost, false, row.MatchOperation)
		page.Rows = append(page.Rows, entry)
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	if err := executeAdminTemplate(w, w, securityEventsTemplate, page); err != nil {
		h.failure(w, r, err)
	}
}

// securityPostURL は公開先の板キーを現在値から解決する。拒否した候補には未公開レスへのリンクを作らない。
func (r *Repository) securityPostURL(board string, thread uint64, number uint32, rejected bool, operation string) string {
	if rejected || board == "" || number == 0 {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, b := range r.posting {
		if id.String() == board {
			if thread == 0 {
				var operationID domain.ID
				if operationID.UnmarshalJSON([]byte(strconv.Quote(operation))) != nil {
					return ""
				}
				value, err := b.worker.Submit(context.Background(), func() (any, error) { return b.operations[operationID], nil })
				if err != nil {
					return ""
				}
				thread = value.(uint64)
				if thread == 0 {
					return ""
				}
			}
			return strings.TrimRight(r.cfg.Public.BaseURL, "/") + fmt.Sprintf("/test/read.cgi/%s/%d/%d", b.slug, thread, number)
		}
	}
	return ""
}

// validSecurityQuery は専用画面の既知の単一項目だけを許可し、別経路へquery許可を広げない。
func validSecurityQuery(r *http.Request) bool {
	if r.Method != "GET" {
		return false
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if path != "/waf-events" && path != "/global-rules" {
		return false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false
	}
	for key, values := range query {
		if len(values) != 1 || len(values[0]) > 4096 {
			return false
		}
		if path == "/global-rules" {
			if key != "event" && key != "q" && key != "state" && key != "limit" && key != "cursor" {
				return false
			}
			continue
		}
		switch key {
		case "source":
			if values[0] != "" && values[0] != "waf" && values[0] != "similar" && values[0] != "flood" && values[0] != "global_rule" {
				return false
			}
		case "result":
			if values[0] != "" && values[0] != "detected" && values[0] != "rejected" {
				return false
			}
		case "reason":
		case "page":
			n, e := strconv.Atoi(values[0])
			if e != nil || n < 1 || n > 10000 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
