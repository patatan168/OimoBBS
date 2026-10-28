// 提出用記録を管理専用リスナーへ登録し、各操作のCSRF・理由・再認証・担当を検査する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"slices"
	"strconv"
	"strings"
	"time"
)

type evidenceInput struct {
	CaseID       domain.ID        `json:"case_id,omitzero"`
	Number       string           `json:"case_number"`
	Organization string           `json:"requesting_organization"`
	Reference    string           `json:"request_reference"`
	Reason       string           `json:"reason"`
	Scope        disclosure.Scope `json:"scope,omitzero"`
	Until        domain.Time      `json:"hold_until_ns"`
	Export       domain.ID        `json:"export_id,omitzero"`
}
type evidenceRow struct {
	Downloads                                                      []evidenceAction
	StateLabel, Until, LogExplanation                              string
	BoardName, BoardKey, From, To, RecordCount, UntilDate, Created string
	Case                                                           disclosure.Case
	Actions                                                        []evidenceAction
	Extract                                                        *evidenceAction
	NeedsHold                                                      bool
	RejectedExtract, HTTPExtract                                   *evidenceAction
	Exports                                                        []evidenceExportRow
}
type evidenceAction struct{ Path, Label, CSRF, Key string }
type evidenceExportRow struct {
	Recoverable         bool
	Created, StateLabel string
	Export              disclosure.Export
	Download            evidenceAction
	Resume              evidenceAction
}
type evidenceView struct {
	Filter                 evidenceListFilter
	Total, Start, End      int
	Rows                   []evidenceRow
	Boards                 []boardOption
	CSRF, Key              string
	OtherCSRF              string
	CleanupFailed          bool
	Next                   string
	DefaultFrom, DefaultTo string
}

var evidenceTemplate = webui.Template("evidence")

func (h *adminHandler) evidenceRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	api := strings.HasPrefix(r.URL.Path, "/api/")
	if r.Method == "GET" {
		h.evidenceGET(w, r, s, path, api)
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if path == "/evidence/query" || strings.HasSuffix(path, "/http-query") || strings.HasSuffix(path, "/rejected-query") || strings.HasSuffix(path, "/query") || strings.HasSuffix(path, "/transfers") {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	input, etag, key, e := h.readEvidenceInput(w, r, s, api)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	if !adminRequestKey.MatchString(key) || etag == "" {
		h.fail(w, r, 400, "EVIDENCE_PRECONDITION_REQUIRED")
		return
	}
	id := input.CaseID
	action := ""
	parts := strings.Split(strings.TrimPrefix(path, "/evidence/"), "/")
	switch {
	case path == "/evidence/cases" || path == "/evidence/other-cases":
		action = "create"
	case len(parts) == 3 && parts[0] == "cases":
		if id.UnmarshalJSON([]byte(strconv.Quote(parts[1]))) != nil || id == (domain.ID{}) {
			h.fail(w, r, 404, "NOT_FOUND")
			return
		}
		action = parts[2]
	case len(parts) == 3 && parts[0] == "exports":
		if input.Export.UnmarshalJSON([]byte(strconv.Quote(parts[1]))) != nil {
			h.fail(w, r, 404, "NOT_FOUND")
			return
		}
		action = parts[2]
		id = input.CaseID
	default:
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	// 提出は記録種別で取り扱える全項目を使う。
	columns := []string{"connection", "content"}
	if strings.HasPrefix(action, "rejected-") {
		columns = []string{"connection"}
	}
	if (action == "extract" || action == "extract-rejected" || action == "extract-http") && parts[0] == "cases" {
		if input.Reason == "" || len(input.Reason) > 2048 {
			h.fail(w, r, 400, "EVIDENCE_REASON_REQUIRED")
			return
		}
		if action != "extract" {
			h.extractOtherEvidence(w, r, s, id, input, etag, key, action == "extract-http")
			return
		}
		h.extractEvidence(w, r, s, id, input, etag, key)
		return
	}
	permissions := map[string]string{"create": "evidence.manage", "hold": "evidence.manage", "http-hold": "evidence.manage", "http-observation-hold": "evidence.manage", "extend": "evidence.manage", "release": "evidence.manage", "rejected-hold": "evidence.manage", "rejected-exports": "evidence.manage", "exports": "evidence.manage", "download": "evidence.manage", "resume": "evidence.manage"}
	permission, ok := permissions[action]
	if !ok {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	// 通常操作を分割した古いHTMLフォームは受け付けない。
	if !api && slices.Contains([]string{"hold", "http-hold", "http-observation-hold", "rejected-hold", "exports", "rejected-exports"}, action) {
		h.repo.mu.Lock()
		current, err := h.repo.evidenceCases.Get(id)
		recovery := err == nil && (action == "hold" && current.State == "preparing" && current.Rejected == nil || action == "http-hold" && current.HTTP != nil && current.HTTP.State == "preparing")
		h.repo.mu.Unlock()
		if !recovery {
			h.fail(w, r, 404, "NOT_FOUND")
			return
		}
	}
	if input.Reason == "" || len(input.Reason) > 2048 {
		h.fail(w, r, 400, "EVIDENCE_REASON_REQUIRED")
		return
	}
	if action == "create" {
		h.repo.mu.Lock()
		e = h.repo.authorizeEvidence(s, permission, input.Scope.Board, true)
		if e == nil && h.repo.boards[input.Scope.Board] == nil {
			e = &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
		}
		h.repo.mu.Unlock()
		if e != nil {
			h.failure(w, r, e)
			return
		}
		if _, e = h.repo.enableStorageReader(r.Context(), 38, "evidence_cases_enable"); e != nil {
			h.failure(w, r, e)
			return
		}
	}
	if action == "rejected-exports" || action == "rejected-hold" {
		minimum := uint32(53)
		if action == "rejected-hold" {
			minimum = 54
		}
		if e = h.repo.prepareRejectedEvidenceAction(r.Context(), s, id, permission, columns, minimum); e != nil {
			h.failure(w, r, evidenceError(e))
			return
		}
	}
	if action == "hold" {
		if err := h.repo.prepareRequiredHoldStorage(r.Context(), s, id, etag, key, input.Reason); err != nil {
			h.failure(w, r, evidenceError(err))
			return
		}
	}
	if action == "http-hold" || action == "http-observation-hold" {
		h.repo.mu.Lock()
		current, err := h.repo.evidenceCases.Get(id)
		if err == nil {
			err = h.repo.authorizeEvidence(s, permission, current.Scope.Board, true)
		}
		if err == nil && h.repo.optionalStore == nil && current.HTTP == nil {
			err = &adminFailure{status: 409, code: "OPTIONAL_HTTP_NOT_ENABLED"}
		}
		if err == nil && action == "http-observation-hold" && !canHoldHTTPObservation(current) {
			err = disclosure.ErrConflict
		}
		hasSource := h.repo.optionalStore != nil
		h.repo.mu.Unlock()
		if err != nil {
			var denied *adminFailure
			if errors.As(err, &denied) && (denied.code == "BOARD_SCOPE_DENIED" || denied.code == "BOARD_SCOPE_REQUIRED") {
				err = &adminFailure{status: 404, code: "EVIDENCE_NOT_FOUND"}
			}
			h.failure(w, r, evidenceError(err))
			return
		}
		version := uint32(41)
		if hasSource {
			version = 42
		}
		if action == "http-observation-hold" {
			version = 57
		}
		if _, err = h.repo.enableStorageReader(r.Context(), version, "http_case_hold_enable"); err != nil {
			h.failure(w, r, err)
			return
		}
		if hasSource {
			if err = h.repo.ensureOptionalHoldStorage(r.Context()); err != nil {
				h.failure(w, r, evidenceError(err))
				return
			}
		}
	}
	h.repo.mu.Lock()
	if e = h.repo.authorizeEvidence(s, permission, domain.ID{}, true); e != nil {
		h.repo.mu.Unlock()
		h.failure(w, r, e)
		return
	}
	board := input.Scope.Board
	var c disclosure.Case
	if action != "create" {
		c, e = h.repo.evidenceCases.Get(id)
		if e == nil {
			board = c.Scope.Board
		}
	}
	if e == nil {
		e = h.repo.authorizeEvidence(s, permission, board, true)
	}
	if e != nil && action != "create" {
		var denied *adminFailure
		if errors.As(e, &denied) && (denied.code == "BOARD_SCOPE_DENIED" || denied.code == "BOARD_SCOPE_REQUIRED") {
			e = &adminFailure{status: 404, code: "EVIDENCE_NOT_FOUND"}
		}
	}
	if e != nil {
		h.repo.mu.Unlock()
		h.failure(w, r, evidenceError(e))
		return
	}
	if action == "rejected-hold" || action == "hold" || action == "http-hold" || action == "http-observation-hold" || action == "exports" || action == "rejected-exports" || action == "resume" {
		release, err := h.repo.reserveEvidence()
		if err != nil {
			h.repo.mu.Unlock()
			h.failure(w, r, err)
			return
		}
		defer release()
	}
	now := time.Now()
	var data any
	switch action {
	case "create":
		c, e = h.repo.evidenceCases.Create(disclosure.Case{Number: input.Number, Organization: input.Organization, Reference: input.Reference, Reason: input.Reason, Until: input.Until, Scope: input.Scope}, s.Admin, etag, key, now)
	case "hold":
		c, e = h.repo.holdRequiredEvidence(r.Context(), s, c, etag, key, input.Reason)
	case "http-hold", "http-observation-hold":
		c, e = h.repo.holdOptionalHTTP(r.Context(), s, c, etag, key, input.Reason, action == "http-observation-hold")
	case "extend":
		c, e = h.repo.extendEvidenceCase(r, s, c, etag, key, input.Reason, input.Until)
	case "release":
		if e = h.repo.ensureCaseCompletionForRequestLocked(c, s.Admin, etag, key, input.Reason, now); e != nil {
			break
		}
		c, e = h.repo.evidenceCases.Release(id, s.Admin, etag, key, input.Reason, now)
		if e == nil {
			var requiredErr, optionalErr error
			c, requiredErr = h.repo.reconcileTerminalRequiredHold(r.Context(), c, h.repo.posting[c.Scope.Board])
			c, optionalErr = h.repo.releaseCancelledOptionalHold(r.Context(), s, c)
			e = errors.Join(requiredErr, optionalErr)
		}
	case "rejected-hold":
		c, e = h.repo.holdRejectedEvidence(r.Context(), s, c, etag, key, input.Reason)
	case "rejected-exports":
		var v disclosure.Export
		c, v, e = h.repo.generateRejectedEvidence(r.Context(), s, c, etag, key, input.Reason, columns)
		data = v
	case "exports":
		if c.HTTP != nil && c.HTTP.Unbound {
			columns = []string{"connection"}
		}
		if c.State == "draft" {
			e = &adminFailure{status: 409, code: "EVIDENCE_HOLD_REQUIRED"}
			break
		}
		var v disclosure.Export
		c, v, e = h.repo.generateEvidence(r.Context(), s, c, etag, key, input.Reason, columns, now)
		data = v
	case "resume":
		var v disclosure.Export
		if isRejectedExport(c, input.Export) {
			c, v, e = h.repo.resumeRejectedEvidence(r.Context(), s, c, input.Export, etag, key, input.Reason)
		} else {
			c, v, e = h.repo.evidenceCases.ResumeExport(id, input.Export, s.Admin, etag, key, input.Reason, now)
		}
		data = v
	case "download":
		updated, file, v, err := h.repo.evidenceCases.Download(id, input.Export, s.Admin, etag, key, input.Reason, now)
		c, e = updated, err
		h.repo.mu.Unlock()
		if e != nil {
			h.failure(w, r, evidenceError(e))
			return
		}
		h.sendEvidenceZIP(w, r, s, c, file, v)
		return
	}
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, evidenceError(e))
		return
	}
	w.Header().Set("ETag", c.ETag())
	if api {
		adminJSON(w, 200, map[string]any{"data": c, "dates": evidenceCaseHTTPValue(c), "result": data, "result_dates": evidenceResultHTTPValue(data), "request_id": domain.NewID()})
		return
	}
	destination := "/evidence"
	if path == "/evidence/other-cases" || c.Rejected != nil || c.HTTP != nil && c.HTTP.Unbound {
		destination += "?kind=other"
	}
	http.Redirect(w, r, destination, 303)
}
func (h *adminHandler) evidenceGET(w http.ResponseWriter, r *http.Request, s adminauth.Session, path string, api bool) {
	if path == "/evidence/sample.zip" {
		h.evidenceSample(w, r)
		return
	}
	if path != "/evidence" && path != "/evidence/cases" && !strings.HasPrefix(path, "/evidence/cases/") {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	if !api {
		h.renderEvidence(w, r, s)
		return
	}
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()
	if e := h.repo.authorizeEvidence(s, "evidence.manage", domain.ID{}, true); e != nil {
		h.failure(w, r, e)
		return
	}
	rows, e := h.repo.evidenceCases.Cases()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	selected := []disclosure.Case{}
	var target domain.ID
	if strings.HasPrefix(path, "/evidence/cases/") {
		if target.UnmarshalJSON([]byte(strconv.Quote(strings.TrimPrefix(path, "/evidence/cases/")))) != nil {
			h.fail(w, r, 404, "NOT_FOUND")
			return
		}
	}
	var window adminListWindow
	var revision string
	if target == (domain.ID{}) {
		rows, window, revision, e = h.repo.evidenceCasePageLocked(rows, s, r)
		if e != nil {
			h.failure(w, r, e)
			return
		}
	}
	tokens := map[string]string{"/api/v1/evidence/cases": s.CSRF("/api/v1/evidence/cases"), "/api/v1/evidence/other-cases": s.CSRF("/api/v1/evidence/other-cases")}
	for _, c := range rows {
		if target != (domain.ID{}) && target != c.ID {
			continue
		}
		if h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true) != nil {
			continue
		}
		selected = append(selected, c)
		for _, action := range []string{"hold", "http-hold", "http-observation-hold", "extend", "release", "exports", "extract", "rejected-hold", "rejected-exports", "extract-rejected", "extract-http"} {
			route := "/api/v1/evidence/cases/" + c.ID.String() + "/" + action
			tokens[route] = s.CSRF(route)
		}
		for _, v := range c.Exports {
			for _, action := range []string{"download", "resume"} {
				route := "/api/v1/evidence/exports/" + v.ID.String() + "/" + action
				tokens[route] = s.CSRF(route)
			}
		}
	}
	etag := `"evidence:new"`
	if target != (domain.ID{}) {
		if len(selected) == 0 {
			h.fail(w, r, 404, "EVIDENCE_NOT_FOUND")
			return
		}
		etag = selected[0].ETag()
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("X-CSRF-Token", s.CSRF("/api/v1/evidence/cases"))
	response := map[string]any{"data": selected, "dates": evidenceCaseHTTPValues(selected), "csrf_tokens": tokens, "cleanup_failed": h.repo.evidenceCleanupFailed}
	if target == (domain.ID{}) {
		response["limit"], response["next_cursor"], response["revision"], response["total"] = window.Limit, window.Next, revision, window.Total
	}
	adminJSON(w, 200, response)
}
func (h *adminHandler) readEvidenceInput(w http.ResponseWriter, r *http.Request, s adminauth.Session, api bool) (evidenceInput, string, string, error) {
	var input evidenceInput
	var etag, key, csrf string
	route := "/api/v1" + strings.TrimPrefix(r.URL.Path, "/api/v1")
	fail := func(code string) (evidenceInput, string, string, error) {
		return input, "", "", &adminFailure{status: 400, code: code}
	}
	if api {
		var e error
		csrf, _, e = singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil || !s.CheckCSRF(route, csrf) {
			return fail("CSRF_REJECTED")
		}
		etag, _, e = singleRequestHeader(r.Header, "If-Match")
		if e != nil {
			return fail("INVALID_REVISION")
		}
		key, _, e = singleRequestHeader(r.Header, "Idempotency-Key")
		if e != nil {
			return fail("INVALID_REQUEST_KEY")
		}
		content, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, _, err := mime.ParseMediaType(content)
		if e != nil || err != nil || media != "application/json" {
			return fail("JSON_REQUIRED")
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if e != nil || decodeEvidenceInput(raw, &input) != nil {
			return fail("INVALID_JSON")
		}
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if r.ParseForm() != nil {
			return fail("INVALID_FORM")
		}
		v := r.PostForm
		allowed := map[string]bool{}
		for _, name := range strings.Fields("csrf revision request_id case_id case_number requesting_organization request_reference reason board_id thread_key from to hold_until export_id") {
			allowed[name] = true
		}
		for name, values := range v {
			if !allowed[name] || len(values) != 1 {
				return fail("INVALID_FORM")
			}
		}
		csrf = v.Get("csrf")
		if !s.CheckCSRF(route, csrf) {
			return fail("CSRF_REJECTED")
		}
		etag, key = v.Get("revision"), v.Get("request_id")
		input.Number = v.Get("case_number")
		if input.Number == "" && (r.URL.Path == "/evidence/cases" || r.URL.Path == "/evidence/other-cases") {
			input.Number = "LOG-" + key
		}
		input.Organization = v.Get("requesting_organization")
		input.Reference = v.Get("request_reference")
		input.Reason = v.Get("reason")
		for name, dst := range map[string]*domain.ID{"case_id": &input.CaseID, "board_id": &input.Scope.Board, "export_id": &input.Export} {
			if raw := v.Get(name); raw != "" && dst.UnmarshalJSON([]byte(strconv.Quote(raw))) != nil {
				return fail("INVALID_ID")
			}
		}
		if raw := v.Get("thread_key"); raw != "" {
			if input.Scope.Thread.UnmarshalJSON([]byte(strconv.Quote(raw))) != nil {
				return fail("INVALID_THREAD")
			}
		}
		for name, dst := range map[string]*domain.Time{"from": &input.Scope.From, "to": &input.Scope.To, "hold_until": &input.Until} {
			if raw := v.Get(name); raw != "" {
				t, e := parseEvidenceDate(raw)
				if e != nil {
					return fail("INVALID_DATE")
				}
				*dst = domain.Time(t.UnixNano())
			}
		}

	}
	return input, etag, key, nil
}
func parseEvidenceDate(raw string) (time.Time, error) {
	if t, e := time.Parse(time.RFC3339Nano, raw); e == nil {
		return t, nil
	}
	if len(raw) == len("2006-01-02T15:04:05") {
		return time.ParseInLocation("2006-01-02T15:04:05", raw, domain.JST)
	}
	return time.ParseInLocation("2006-01-02T15:04", raw, domain.JST)
}
func (h *adminHandler) renderEvidence(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	h.repo.mu.Lock()
	e := h.repo.authorizeEvidence(s, "evidence.manage", domain.ID{}, true)
	if e != nil {
		h.repo.mu.Unlock()
		var failure *adminFailure
		if errors.As(e, &failure) && failure.code == "EVIDENCE_PERMISSION_REQUIRED" {
			h.evidencePermissionPage(w, r, s)
			return
		}
		h.failure(w, r, e)
		return
	}
	if r.URL.Path == "/evidence" && r.URL.RawQuery == "" && r.Context().Value(adminAssetCheckContextKey{}) == true {
		h.repo.mu.Unlock()
		renderAdminAssetOnly(w, r, evidenceTemplate, evidenceView{})
		return
	}
	filter, e := readEvidenceListFilter(evidenceHTMLListRequest(r))
	if e != nil {
		h.repo.mu.Unlock()
		h.failure(w, r, e)
		return
	}
	cases, e := h.repo.evidenceCases.Cases()
	now := time.Now().In(domain.JST)
	view := evidenceView{OtherCSRF: s.CSRF("/api/v1/evidence/other-cases"), Filter: filter, DefaultFrom: now.Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano), DefaultTo: now.Format(time.RFC3339Nano), Rows: []evidenceRow{}, CSRF: s.CSRF("/api/v1/evidence/cases"), Key: domain.NewID().String(), CleanupFailed: h.repo.evidenceCleanupFailed}
	if e == nil {
		var window adminListWindow
		cases, window, _, e = h.repo.evidenceCasePageLocked(cases, s, evidenceHTMLListRequest(r))
		view.Next = filter.NextLink("/evidence", window)
		view.Total, view.Start, view.End = window.Total, window.Start+1, window.End
	}
	if e == nil {
		for _, c := range cases {
			if h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true) != nil {
				continue
			}
			row := evidenceRow{Case: c, StateLabel: map[string]string{"draft": "作成済み・保全前", "preparing": "保全コピー作成中", "active": "案件保全中", "partial": "一部の対象が欠落", "releasing": "解除・回収中", "closed": "保全解除・回収済み"}[c.State], Until: time.Unix(0, int64(c.Until)).In(domain.JST).Format("2006-01-02 15:04:05")}
			row.Created = time.Unix(0, int64(c.Created)).In(domain.JST).Format("2006-01-02 15:04:05")
			row.UntilDate = time.Unix(0, int64(c.Until)).In(domain.JST).Format("2006-01-02")
			row.BoardName = "保存済みの板"
			if board := h.repo.posting[c.Scope.Board]; board != nil {
				row.BoardName, row.BoardKey = board.boardName(), board.boardKey()
			}
			row.From = time.Unix(0, int64(c.Scope.From)).In(domain.JST).Format("2006-01-02 15:04")
			row.To = time.Unix(0, int64(c.Scope.To)).In(domain.JST).Format("2006-01-02 15:04")
			row.RecordCount = strconv.Itoa(len(c.Items)) + "投稿"
			if c.State == "draft" {
				row.RecordCount = "未確定"
			} else if c.Rejected != nil {
				row.RecordCount = strconv.Itoa(len(c.Rejected.Items)) + "件（未受理）"
			} else if c.HTTP != nil && c.HTTP.Unbound {
				row.RecordCount = strconv.Itoa(len(c.HTTP.Items)) + "件（HTTP）"
			}
			row.LogExplanation = evidenceStorageSummary(c, now)

			row.NeedsHold = c.State == "draft"
			if filter.Kind == "posts" && now.UnixNano() < int64(c.Until) && (c.State == "active" || c.State == "partial" || row.NeedsHold) && c.Rejected == nil && (c.HTTP == nil || !c.HTTP.Unbound) {
				path := "/evidence/cases/" + c.ID.String() + "/extract"
				row.Extract = &evidenceAction{path, "ZIPを作成してダウンロード", s.CSRF("/api/v1" + path), domain.NewID().String()}
			}
			configureEvidenceActions(&row, s, filter.Kind, now)

			view.Rows = append(view.Rows, row)
		}
	}
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	view.Boards, e = h.repo.boardOptions(s, nil)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	var buf bytes.Buffer
	if e = executeAdminTemplate(w, &buf, evidenceTemplate, view); e != nil {
		h.failure(w, r, e)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	_, _ = w.Write(buf.Bytes())
}

// decodeEvidenceInput は要求用の省略可能な項目を、重複・未知キーを拒否して読み込む。
func decodeEvidenceInput(raw []byte, input *evidenceInput) error {
	if err := strictjson.Validate(raw); err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return disclosure.ErrInvalid
	}
	raw, err := evidenceRequestDates(raw)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(input)
}

// showRejectedHoldAction は新規保全と未完成コピーの再開だけを画面へ表示する。
func showRejectedHoldAction(c disclosure.Case) bool {
	switch c.State {
	case "draft":
		return c.Rejected == nil && c.HTTP == nil
	case "preparing":
		return c.Rejected != nil && c.Rejected.State == "preparing"
	default:
		return false
	}
}

// canHoldHTTPObservation は別の空案件か、同じ固定HTTP案件の再開だけを許可する。
func canHoldHTTPObservation(c disclosure.Case) bool {
	if c.Scope.Thread != 0 || len(c.Items) > 0 || c.Required != nil || c.Rejected != nil {
		return false
	}
	if c.HTTP == nil {
		return c.State == "draft" && len(c.Exports) == 0
	}
	return c.HTTP.Unbound && slices.Contains([]string{"preparing", "active", "partial"}, c.State)
}

// evidencePermissionPage は閲覧権限不足を説明し、特権管理者だけを自身の権限設定へ案内する。
func (h *adminHandler) evidencePermissionPage(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	h.repo.mu.Lock()
	a, e := h.repo.currentAdminSession(s)
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	page := adminPage{Title: "提出用ログの閲覧権限が必要です", Message: "追加権限「提出用ログを閲覧」が必要です。サイト管理者に設定を依頼してください。", BackPath: "/"}
	if a.Role == "site_admin" {
		page.Message = "特権管理者も追加権限「提出用ログを閲覧」の設定が必要です。自分の権限設定でチェックして保存し、再ログインしてください。"
		page.ActionPath = "/administrators/" + s.Admin.String()
		page.ActionLabel = "自分の権限設定へ進む"
	}
	writeAdminPage(w, 403, page)
}
