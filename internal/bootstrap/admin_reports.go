// 担当板の非公開依頼を一覧・回答し、IPと照会秘密を通常管理画面へ出さない。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminaccess"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/webui"
)

type adminReportView struct {
	ID        domain.ID   `json:"id"`
	Board     domain.ID   `json:"board_id"`
	Thread    domain.U64  `json:"thread_key"`
	Ranges    string      `json:"ranges"`
	Category  string      `json:"category"`
	Reason    string      `json:"reason"`
	Contact   string      `json:"contact"`
	State     string      `json:"state"`
	Assignee  *domain.ID  `json:"assignee_id"`
	Answer    string      `json:"answer"`
	Duplicate *domain.ID  `json:"duplicate_of"`
	Expires   domain.Time `json:"expires_at_ns"`
	Revision  uint64      `json:"revision"`
}

func reportView(v deletionReport) adminReportView {
	return adminReportView{v.ID, v.Board, v.Thread, v.Ranges, v.Category, v.Reason, v.Contact, v.State, v.Assignee, v.Answer, v.Duplicate, v.Expires, v.Revision}
}

type adminReportsPage struct {
	Title, CSRF, Next string
	Reports           []adminReportView
	Report            *adminReportView
}

var adminReportsTemplate = webui.Template("admin-reports")

// privateReportAdministrator は非公開依頼の一覧・回答に必要な役割と明示権限を現在値で検査する。
// 呼出元はsite mutexを保持する。
func (repo *Repository) privateReportAdministrator(s adminauth.Session) (administrator, error) {
	a, err := repo.currentAdminSession(s)
	if err != nil {
		return a, err
	}
	permission, _ := adminaccess.LookupPermission("private_reports.read")
	if adminRoleRank[a.Role] < permission.MinimumRank() {
		return a, &adminFailure{status: 403, code: "PERMISSION_DENIED"}
	}
	if !adminaccess.Granted(a.Role, a.Permissions, "private_reports.read") {
		return a, &adminFailure{status: 403, code: "PRIVATE_REPORT_PERMISSION_REQUIRED"}
	}
	return a, nil
}

// reportRoutes は管理の現在認可・CSRF・file版を使い、依頼閲覧と回答更新を振り分ける。
func (h *adminHandler) reportRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	if r.Method == "GET" {
		page, e := h.repo.adminReports(s, path, r.URL.RawQuery)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		page.CSRF = s.CSRF(path)
		// 保存時の世代変更やログアウト後に、読み込み済みの私情報を送信しない。
		w = &evidenceQueryWriter{ResponseWriter: w, check: func() error {
			h.repo.mu.Lock()
			defer h.repo.mu.Unlock()
			a, err := h.repo.privateReportAdministrator(s)
			if err != nil {
				return err
			}
			if page.Report != nil {
				return authorizeAdministrator(a, "moderator", page.Report.Board)
			}
			for _, report := range page.Reports {
				if err := authorizeAdministrator(a, "moderator", report.Board); err != nil {
					return err
				}
			}
			return nil
		}}
		w.Header().Set("X-CSRF-Token", page.CSRF)
		if api {
			if page.Next != "" {
				_, base, _ := h.repo.cfg.adminEndpoint()
				page.Next = base + page.Next
			}
			adminJSON(w, 200, map[string]any{"data": page.Reports, "report": page.Report, "next": page.Next})
			return
		}
		var buffer bytes.Buffer
		if e = executeAdminTemplate(w, &buffer, adminReportsTemplate, page); e != nil {
			h.fail(w, r, 500, "TEMPLATE_ERROR")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(buffer.Bytes())
		return
	}
	if r.Method != "POST" || api || path == "/reports" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	fields, e := adminForm(w, r, 32<<10, "csrf", "revision", "state", "answer", "duplicate_of")
	if e != nil {
		h.fail(w, r, 400, "INVALID_FORM")
		return
	}
	if !s.CheckCSRF(path, fields.Get("csrf")) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	if e := h.repo.updateReport(s, path, fields.Get("revision"), fields.Get("state"), fields.Get("answer"), fields.Get("duplicate_of")); e != nil {
		h.failure(w, r, e)
		return
	}
	http.Redirect(w, r, path, 303)
}

// adminReports は現在の担当板だけを100件ずつ返し、通常DTOへIPや秘密hashを含めない。
func (repo *Repository) adminReports(s adminauth.Session, path, query string) (adminReportsPage, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	a, e := repo.privateReportAdministrator(s)
	if e != nil {
		return adminReportsPage{}, e
	}
	page := adminReportsPage{Title: "削除依頼・照会", Reports: []adminReportView{}}
	if _, enabled := repo.site.State().Rows["report_store:active"]; !enabled {
		if path == "/reports" {
			return page, nil
		}
		return page, &adminFailure{status: 404, code: "NOT_FOUND"}
	}
	key, e := reportKey(repo.cfg.DataDir)
	if e != nil {
		return page, e
	}
	defer clear(key[:])
	if path != "/reports" {
		id, e := parseReportID(strings.TrimPrefix(path, "/reports/"))
		if e != nil {
			return page, &adminFailure{status: 404, code: "NOT_FOUND"}
		}
		v, e := readReport(repo.cfg.DataDir, id, key)
		if errors.Is(e, os.ErrNotExist) || v.Expires <= domain.Time(time.Now().UnixNano()) {
			return page, &adminFailure{status: 404, code: "NOT_FOUND"}
		}
		if e != nil {
			return page, e
		}
		if e = repo.authorizeAdmin(s, "moderator", v.Board); e != nil {
			return page, e
		}
		view := reportView(v)
		page.Report = &view
		return page, nil
	}
	after := ""
	if query != "" {
		if !validReportQuery(query) {
			return page, &adminFailure{status: 400, code: "INVALID_QUERY"}
		}
		after = strings.TrimPrefix(query, "after=")
	}
	ids, e := reportFiles(repo.cfg.DataDir)
	if e != nil {
		return page, e
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	for _, id := range ids {
		if id.String() <= after {
			continue
		}
		v, e := readReport(repo.cfg.DataDir, id, key)
		if e != nil {
			return page, e
		}
		if v.Expires <= domain.Time(time.Now().UnixNano()) || authorizeAdministrator(a, "moderator", v.Board) != nil {
			continue
		}
		if len(page.Reports) == 100 {
			page.Next = "/reports?after=" + page.Reports[99].ID.String()
			break
		}
		page.Reports = append(page.Reports, reportView(v))
	}
	return page, nil
}
func validReportQuery(raw string) bool {
	_, e := parseReportID(strings.TrimPrefix(raw, "after="))
	return strings.HasPrefix(raw, "after=") && e == nil
}

// updateReport は現在認可とfile版を確認し、固定監査intentの後で回答fileを一括置換する。
func (repo *Repository) updateReport(s adminauth.Session, path, revision, state, answer, duplicate string) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if e := repo.available(); e != nil {
		return e
	}
	_, e := repo.privateReportAdministrator(s)
	if e != nil {
		return e
	}
	id, e := parseReportID(strings.TrimPrefix(path, "/reports/"))
	if e != nil {
		return &adminFailure{status: 404, code: "NOT_FOUND"}
	}
	key, e := reportKey(repo.cfg.DataDir)
	if e != nil {
		return e
	}
	defer clear(key[:])
	v, e := readReport(repo.cfg.DataDir, id, key)
	if errors.Is(e, os.ErrNotExist) {
		return &adminFailure{status: 404, code: "NOT_FOUND"}
	}
	if e != nil {
		return e
	}
	if e = repo.authorizeAdmin(s, "moderator", v.Board); e != nil {
		return e
	}
	now := domain.Time(time.Now().UnixNano())
	if now < v.Updated || int64(now) < repo.controlExpiryFloor.Load() {
		return ErrControlExpiryClock
	}
	if v.Expires <= now {
		return &adminFailure{status: 404, code: "NOT_FOUND"}
	}
	if revision != strconv.FormatUint(v.Revision, 10) {
		return &adminFailure{status: 409, code: "REVISION_CONFLICT"}
	}
	if v.Revision == ^uint64(0) {
		return store.ErrCorrupt
	}
	if state == "open" {
		return &adminFailure{status: 400, code: "INVALID_STATE"}
	}
	v.State, v.Answer, v.Assignee = state, answer, &s.Admin
	v.Duplicate = nil
	if state == "duplicate" {
		target, e := parseReportID(duplicate)
		if e != nil {
			return &adminFailure{status: 400, code: "INVALID_DUPLICATE"}
		}
		if e = repo.checkReportDuplicate(s, id, target, key); e != nil {
			return e
		}
		v.Duplicate = &target
	} else if duplicate != "" {
		return &adminFailure{status: 400, code: "INVALID_DUPLICATE"}
	}
	if state == "resolved" || state == "rejected" || state == "duplicate" {
		if v.Resolved == nil {
			v.Resolved = &now
		}
		v.Expires = min(v.Expires, now+30*86400e9)
	}
	v.Updated = now
	v.Revision++
	if e = validateReport(v); e != nil {
		return &adminFailure{status: 400, code: "INVALID_REPORT"}
	}
	input, _ := json.Marshal(v)
	request := identity.MAC(key[:], "oimo/report-update/v1", input)
	requestKey := identity.MAC(key[:], "oimo/report-update-key/v1", []byte(id.String()), []byte(revision))
	kid := uint32(6)
	actor := domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "report_update", Request: &request, Idempotency: &requestKey, KeyID: &kid}
	activation := json.RawMessage(repo.site.State().Rows["report_store:active"].Value)
	frame, e := controlFrame(repo.site.State(), domain.NewID(), now, "report_update", []store.Mutation{mutation("report_store", "active", activation, nil)}, []string{id.String()}, actor)
	if e != nil {
		return e
	}
	if repo.site.Append(frame).Status != store.Durable {
		repo.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN"}
	}
	repo.reportMu.Lock()
	defer repo.reportMu.Unlock()
	if e = writeReport(repo.cfg.DataDir, v, key); e != nil {
		repo.stopped = true
		return e
	}
	return nil
}

// checkReportDuplicate は現在認可で辿れる期限内の依頼だけを使い、自己参照/循環を有界に拒否する。
func (repo *Repository) checkReportDuplicate(s adminauth.Session, id, target domain.ID, key [32]byte) error {
	for range reportLimit {
		if target == id {
			return &adminFailure{status: 400, code: "INVALID_DUPLICATE"}
		}
		v, e := readReport(repo.cfg.DataDir, target, key)
		if e != nil || v.Expires <= domain.Time(time.Now().UnixNano()) {
			return &adminFailure{status: 400, code: "INVALID_DUPLICATE"}
		}
		if e = repo.authorizeAdmin(s, "moderator", v.Board); e != nil {
			return e
		}
		if v.Duplicate == nil {
			return nil
		}
		target = *v.Duplicate
	}
	return fmt.Errorf("report duplicate chain exceeds limit")
}
