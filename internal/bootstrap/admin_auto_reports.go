// 担当板の自動停止を一覧化し、権限付き原本閲覧と再認証後の手動規制へ接続する。
package bootstrap

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
)

type autoReportStopRow struct {
	Board, ID             domain.ID
	Name, At, State, Path string
}
type autoReportContent struct {
	Target, TargetBody, ReportBody, At, Source, Message string
	until                                               domain.Time
	private                                             bool
}
type autoReportsPage struct {
	Rows                                                                                            []autoReportStopRow
	Contents                                                                                        []autoReportContent
	Next, Path, Name, At, State, CSRF, InspectCSRF, Revision, RequestID, PermanentRequestID, Reauth string
	Detail, CanRead, CanRule, Fresh                                                                 bool
}

type autoReportContentGroup struct {
	Target, TargetBody string
	Reports            []autoReportContent
}

// ContentGroups は同じレスへの通報をまとめ、異なるレスと特定できない通報は分けて表示する。
func (p autoReportsPage) ContentGroups() []autoReportContentGroup {
	groups := []autoReportContentGroup{}
	indices := map[string]int{}
	for _, report := range p.Contents {
		i, found := indices[report.Target]
		if report.Target == "" || !found {
			i = len(groups)
			groups = append(groups, autoReportContentGroup{Target: report.Target, TargetBody: report.TargetBody})
			if report.Target != "" {
				indices[report.Target] = i
			}
		}
		groups[i].Reports = append(groups[i].Reports, report)
	}
	return groups
}

var autoReportsTemplate = webui.Template("admin-auto-reports")

func writeAutoReports(w http.ResponseWriter, p autoReportsPage) {
	var body bytes.Buffer
	if err := executeAdminTemplate(w, &body, autoReportsTemplate, p); err != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body.Bytes())
}

// autoReportRoutes は担当板と操作別CSRFを検査し、GETで非公開原本を開かない。
func (h *adminHandler) autoReportRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if r.URL.Path == "/auto-reports" {
		h.autoReportList(w, r, s)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/auto-reports/"), "/")
	var owner, id domain.ID
	if len(parts) < 2 || len(parts) > 3 || owner.UnmarshalJSON([]byte(strconv.Quote(parts[0]))) != nil || id.UnmarshalJSON([]byte(strconv.Quote(parts[1]))) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	path := fmt.Sprintf("/auto-reports/%s/%s", owner, id)
	h.repo.mu.Lock()
	err := h.repo.authorizeAdmin(s, "moderator", owner)
	b := h.repo.posting[owner]
	var rule denialRule
	var page autoReportsPage
	if err == nil && b != nil {
		_, err = b.worker.Submit(r.Context(), func() (any, error) {
			entry, ok := b.denials[id]
			if !ok || !automaticStopRule(entry.rule) {
				return nil, &adminFailure{status: 404, code: "NOT_FOUND"}
			}
			rule = entry.rule
			page = autoReportsPage{Detail: true, Path: path, Name: b.publicName, At: reportReviewTime(rule.Starts), State: reportStopState(rule), Revision: b.adminRules().ETag()}
			return nil, nil
		})
	} else if err == nil {
		err = &adminFailure{status: 404, code: "NOT_FOUND"}
	}
	page.CanRead = h.repo.authorizeEvidence(s, "evidence.manage", owner, false) == nil
	page.CanRule = h.repo.authorizeAdmin(s, "board_admin", owner) == nil
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	page.Fresh = s.Reauthenticated(time.Now())
	page.CSRF = s.CSRF(path + "/rule")
	page.InspectCSRF = s.CSRF(path + "/inspect")
	page.RequestID = domain.NewID().String()
	page.PermanentRequestID = domain.NewID().String()
	page.Reauth = "/reauth?" + url.Values{"return_to": {path}}.Encode()
	if r.Method == "GET" && len(parts) == 2 {
		writeAutoReports(w, page)
		return
	}
	if r.Method != "POST" || len(parts) != 3 {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if parts[2] != "inspect" && parts[2] != "rule" {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	names := []string{"csrf", "request_id"}
	if parts[2] == "rule" {
		names = append(names, "revision", "duration", "minutes", "confirm")
	}
	fields, err := adminForm(w, r, 8<<10, names...)
	if err != nil || !adminRequestKey.MatchString(fields.Get("request_id")) {
		h.fail(w, r, 400, "INVALID_FORM")
		return
	}
	if !s.CheckCSRF(r.URL.Path, fields.Get("csrf")) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	if parts[2] == "rule" && !page.Fresh {
		http.Redirect(w, r, page.Reauth, http.StatusSeeOther)
		return
	}
	if parts[2] == "inspect" {
		page.Contents, err = h.repo.reviewAutoReportContents(r.Context(), s, b, rule, fields.Get("request_id"))
		if err != nil {
			h.failure(w, r, err)
			return
		}
		writeAutoReports(h.checkedAutoReportWriter(w, s, owner, page.Contents), page)
		return
	}
	if fields.Get("confirm") != "yes" {
		h.fail(w, r, 400, "INVALID_FORM")
		return
	}
	var minutes uint64
	switch fields.Get("duration") {
	case "permanent":
		minutes = uint64(permanentDenyMinutes)
	case "temporary":
		var e error
		minutes, e = strconv.ParseUint(fields.Get("minutes"), 10, 32)
		if e != nil || minutes < 1 || minutes > maxDenyMinutes {
			h.fail(w, r, 422, "INVALID_RULE")
			return
		}
	default:
		h.fail(w, r, 422, "INVALID_RULE")
		return
	}
	input := AdminRuleInput{Target: rule.Conditions[0].Value, Operations: []string{"create", "reply"}, Minutes: uint32(minutes), Reason: "abuse", Match: &AdminRuleMatch{"token", "exact", "deny"}}
	if _, err = h.repo.changeRule(r.Context(), s, owner, domain.ID{}, input, fields.Get("revision"), fields.Get("request_id")); err != nil {
		h.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/boards/"+owner.String()+"/rules", 303)
}

// checkedAutoReportWriter は帯域待ち・各送信片の直前に、原本の権限と保持期限を再検査する。
func (h *adminHandler) checkedAutoReportWriter(w http.ResponseWriter, s adminauth.Session, owner domain.ID, contents []autoReportContent) http.ResponseWriter {
	return &adminCheckedWriter{ResponseWriter: w, check: func() error {
		h.repo.mu.Lock()
		defer h.repo.mu.Unlock()
		if err := h.repo.authorizeEvidence(s, "evidence.manage", owner, true); err != nil {
			return err
		}
		for _, content := range contents {
			if content.private {
				if _, err := h.repo.privateReportAdministrator(s); err != nil {
					return err
				}
			}
			if content.until != 0 && domain.Time(time.Now().UnixNano()) >= content.until {
				return &adminFailure{status: 403, code: "EVIDENCE_EXPIRED"}
			}
		}
		return nil
	}}
}

// autoReportList は原本本文や匿名主体を出さず、担当板内の停止履歴をページ送りする。
func (h *adminHandler) autoReportList(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if r.Method != "GET" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	h.repo.mu.Lock()
	a, err := h.repo.currentAdminSession(s)
	if err == nil && r.URL.RawQuery == "" && r.Context().Value(adminAssetCheckContextKey{}) == true {
		h.repo.mu.Unlock()
		renderAdminAssetOnly(w, r, autoReportsTemplate, autoReportsPage{})
		return
	}
	rows := []autoReportStopRow{}
	if err == nil {
		for owner, b := range h.repo.posting {
			if authorizeAdministrator(a, "moderator", owner) != nil {
				continue
			}
			_, err = b.worker.Submit(r.Context(), func() (any, error) {
				for _, entry := range b.denials {
					rule := entry.rule
					if automaticStopRule(rule) {
						rows = append(rows, autoReportStopRow{owner, rule.ID, b.publicName, reportReviewTime(rule.Starts), reportStopState(rule), fmt.Sprintf("/auto-reports/%s/%s", owner, rule.ID)})
					}
				}
				return nil, nil
			})
			if err != nil {
				break
			}
		}
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if (rows[i].State == "一時停止中") != (rows[j].State == "一時停止中") {
			return rows[i].State == "一時停止中"
		}
		if rows[i].At != rows[j].At {
			return rows[i].At > rows[j].At
		}
		return rows[i].Path < rows[j].Path
	})
	revision, err := adminListRevision(rows)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	keys := make([]string, len(rows))
	for i, row := range rows {
		keys[i] = row.Path
	}
	window, err := adminListSlice(r, s, revision, keys, time.Now())
	if err != nil {
		h.failure(w, r, err)
		return
	}
	writeAutoReports(w, autoReportsPage{Rows: rows[window.Start:window.End], Next: adminNextLink(r.URL.Path, window)})
}
func reportReviewTime(at domain.Time) string {
	return time.Unix(0, int64(at)).In(time.FixedZone("JST", 9*3600)).Format("2006/01/02 15:04:05")
}
func reportStopState(r denialRule) string {
	if !r.Enabled {
		return "解除済み"
	}
	if r.Expires <= domain.Time(time.Now().UnixNano()) {
		return "満了"
	}
	return "一時停止中"
}
