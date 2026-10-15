// 管理人のレス閲覧から既存の削除・規制・記録提出へ接続する。公開ルーターでは登録しない。
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/textcodec"
	"oimobbs/internal/webui"
)

type adminPostRow struct {
	Number                                                           uint32
	Name, Mail, Date, Body, Base, DeleteCSRF, InspectCSRF, RequestID string
}
type adminPostRecord struct {
	Number                                                              uint32
	Record, Operation, At, IP, Subject, Base, CSRF, RuleCSRF, RequestID string
	Agents                                                              []string
}
type adminPostsPage struct {
	Board, Base, Title, Revision, Previous, Next, Reauth, Message string
	Rows                                                          []adminPostRow
	Records                                                       []adminPostRecord
	Selected                                                      uint32
	Related                                                       string
	CanRead, CanRule, CanExport, Fresh                            bool
	CSRF, RequestID, Selection, LookupCSRF, LookupRequestID       string
}

var adminPostsTemplate = webui.Template("admin-posts")

// adminPostsPath は専用管理経路と番号を厳密に解釈する。クエリへ私情報を持ち込まない。
func adminPostsPath(path string) (owner domain.ID, key uint64, parts []string, ok bool) {
	if !strings.HasPrefix(path, "/boards/") {
		return
	}
	parts = strings.Split(strings.TrimPrefix(path, "/boards/"), "/")
	if len(parts) < 5 || parts[1] != "threads" || parts[3] != "posts" || owner.UnmarshalJSON([]byte(strconv.Quote(parts[0]))) != nil || owner == (domain.ID{}) {
		return
	}
	var err error
	key, err = strconv.ParseUint(parts[2], 10, 64)
	ok = err == nil && key != 0 && strconv.FormatUint(key, 10) == parts[2]
	return
}

// adminPosts は公開表示の50レス単位閲覧と、レス番号へ束縛したPOST操作だけを受け付ける。
func (h *adminHandler) adminPosts(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	owner, key, parts, ok := adminPostsPath(r.URL.Path)
	if !ok {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	h.repo.mu.Lock()
	err := h.repo.authorizeAdmin(s, "moderator", owner)
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	base := fmt.Sprintf("/boards/%s/threads/%d/posts", owner, key)
	number, err := strconv.ParseUint(parts[4], 10, 32)
	if err != nil || number == 0 || strconv.FormatUint(number, 10) != parts[4] {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	if r.Method == "GET" && len(parts) == 5 {
		h.postsPage(w, r, s, owner, key, uint32(number), nil, "post", 0)
		return
	}
	if r.Method != "POST" || len(parts) != 6 {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	action := parts[5]
	names := []string{"csrf", "request_id"}
	switch action {
	case "delete":
		names = append(names, "revision", "confirm")
	case "inspect":
		names = append(names, "related")
	case "lookup":
		names = append(names, "response_number")
	case "export":
		names = append(names, "related", "selection")
	case "rule":
		names = append(names, "kind")
	default:
		h.fail(w, r, 404, "NOT_FOUND")
		return
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
	if action == "lookup" {
		n, e := strconv.ParseUint(fields.Get("response_number"), 10, 32)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != fields.Get("response_number") {
			h.fail(w, r, 400, "INVALID_RESPONSE_NUMBER")
			return
		}
		number = n
		action = "inspect"
		fields.Set("related", "post")
	}

	if action == "delete" {
		if fields.Get("confirm") != "yes" {
			h.fail(w, r, 400, "DELETION_CONFIRMATION_REQUIRED")
			return
		}
		edit := AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: uint32(number), Last: uint32(number), Mode: "aboon"}}}
		_, err = h.repo.ModerateThread(r.Context(), s, owner, key, edit, fields.Get("revision"), fields.Get("request_id"))
		if err != nil {
			h.failure(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%s/%d#post-%d", base, ((number-1)/50)*50+1, number), 303)
		return
	}
	related := "post"
	if action == "inspect" || action == "export" {
		related = fields.Get("related")
	}
	if !slices.Contains([]string{"post", "ip", "token"}, related) {
		h.fail(w, r, 400, "INVALID_SELECTION")
		return
	}
	h.repo.mu.Lock()
	err = h.repo.authorizeEvidence(s, "evidence.manage", owner, true)
	if err == nil && action == "rule" {
		err = h.repo.authorizeAdmin(s, "board_admin", owner)
	}
	if action == "export" {
		for _, permission := range []string{"evidence.manage"} {
			if err == nil {
				err = h.repo.authorizeEvidence(s, permission, owner, true)
			}
		}
	}
	b := h.repo.posting[owner]
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if b == nil {
		h.fail(w, r, 404, "BOARD_NOT_FOUND")
		return
	}
	value, err := b.worker.Submit(r.Context(), func() (any, error) {
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		journals := make([]*evidence.Journal, 0, len(b.journals))
		for _, journal := range b.journals {
			journals = append(journals, journal)
		}
		return app.AcceptedRecordsForPost(journals, owner, domain.U64(key), uint32(number), related, domain.Time(time.Now().UnixNano()), disclosure.MaxRecords)
	})
	if errors.Is(err, app.ErrEvidenceIdentityUnavailable) {
		h.fail(w, r, 422, "EVIDENCE_IDENTITY_UNAVAILABLE")
		return
	}
	if errors.Is(err, app.ErrEvidenceSelectionLimit) {
		h.fail(w, r, 422, "EVIDENCE_SCOPE_LIMIT")
		return
	}
	if err != nil {
		h.failure(w, r, err)
		return
	}
	rows := value.([]app.AcceptedEvidence)
	if len(rows) == 0 {
		h.fail(w, r, 404, "POST_EVIDENCE_NOT_FOUND")
		return
	}
	slices.SortFunc(rows, func(a, b app.AcceptedEvidence) int { return int(a.Post) - int(b.Post) })
	if action == "export" && fields.Get("selection") != postEvidenceSelection(rows) {
		h.fail(w, r, 412, "EVIDENCE_SELECTION_CHANGED")
		return
	}
	if _, err = h.repo.enableStorageReader(r.Context(), 64, "post_evidence_query_enable"); err != nil {
		h.failure(w, r, err)
		return
	}
	// 操作者・対象原本IDだけを板controlへ耐久監査する。IP/UA/主体HMACを一般監査へ複製しない。
	h.repo.mu.Lock()
	err = h.repo.authorizeEvidence(s, "evidence.manage", owner, true)
	if err == nil {
		_, err = b.worker.Submit(r.Context(), func() (any, error) {
			if b.stopped {
				return nil, ErrPostingUnavailable
			}
			targets := make([]string, len(rows))
			for i, row := range rows {
				targets[i] = row.RecordID.String()
			}
			at := domain.Time(time.Now().UnixNano())
			ids := make([]domain.ID, len(rows))
			for i, row := range rows {
				ids[i] = row.RecordID
			}
			requestKey := identity.MAC(b.dedupKey[:], "oimo/post-evidence-query-key/v1", s.Admin[:], []byte(fields.Get("request_id")))
			request := identity.MAC(b.dedupKey[:], "oimo/post-evidence-query/v1", s.Admin[:], []byte(r.URL.Path), []byte(related), []byte(postEvidenceSelection(rows)))
			keyID := uint32(8)
			frame, e := controlFrame(b.control.State(), domain.NewID(), at, "post_evidence_query", []store.Mutation{mutation("post_evidence_query", "latest", postEvidenceAudit{Actor: s.Admin, At: at, Records: ids}, nil)}, targets, domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "post_evidence_query", Request: &request, Idempotency: &requestKey, KeyID: &keyID})
			if e != nil {
				return nil, e
			}
			if b.control.Append(frame).Status != store.Durable {
				b.stopped = true
				return nil, ErrPostingUnavailable
			}
			return nil, nil
		})
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if action == "export" {
		h.exportPostEvidence(w, r, s, owner, key, rows, fields.Get("request_id"))
		return
	}
	if action == "rule" {
		h.prefillPostRule(w, r, s, owner, rows[0], fields.Get("kind"))
		return
	}
	h.postsPage(w, r, s, owner, key, uint32((number-1)/50*50+1), rows, related, uint32(number))
}

// postsPage は公開DATだけを表示し、削除後の原文を通常閲覧へ復活させない。
func (h *adminHandler) postsPage(w http.ResponseWriter, r *http.Request, s adminauth.Session, owner domain.ID, key uint64, from uint32, records []app.AcceptedEvidence, related string, selected uint32) {
	base := fmt.Sprintf("/boards/%s/threads/%d/posts", owner, key)
	page := adminPostsPage{LookupCSRF: s.CSRF(base + "/1/lookup"), LookupRequestID: domain.NewID().String(), Board: owner.String(), Base: base, Related: related, Fresh: s.Reauthenticated(time.Now()), Reauth: "/reauth?" + url.Values{"return_to": {fmt.Sprintf("%s/%d", base, from)}}.Encode()}
	h.repo.mu.Lock()
	page.CanRead = h.repo.authorizeEvidence(s, "evidence.manage", owner, false) == nil
	page.CanRule = h.repo.authorizeAdmin(s, "board_admin", owner) == nil
	page.CanExport = page.CanRead
	b := h.repo.posting[owner]
	h.repo.mu.Unlock()
	if b == nil {
		h.fail(w, r, 404, "BOARD_NOT_FOUND")
		return
	}
	snapshot, status := b.publicSnapshot(key, domain.Time(time.Now().UnixNano()))
	var lease *app.PublicLease
	if status == 200 {
		var err error
		lease, err = snapshot.AcquirePublic(domain.Time(time.Now().UnixNano()), func() {})
		if err != nil {
			h.failure(w, r, err)
			return
		}
		defer lease.Close()
		page.Title = snapshot.Title
		page.Revision = fmt.Sprintf(`"%s:%d:%d"`, owner, key, snapshot.Revision)
		lines := bytes.Split(snapshot.DAT, []byte{'\n'})
		total := len(lines)
		if total > 0 && len(lines[total-1]) == 0 {
			total--
		}
		if int(from) > max(1, total) {
			h.fail(w, r, 404, "NOT_FOUND")
			return
		}
		for i := int(from) - 1; i < min(total, int(from)+49); i++ {
			decoded, err := textcodec.Decode(lines[i])
			if err != nil {
				h.failure(w, r, err)
				return
			}
			values := strings.Split(decoded, "<>")
			if len(values) != 5 {
				h.fail(w, r, 500, "INVALID_PUBLIC_DAT")
				return
			}
			n := uint32(i + 1)
			actionBase := fmt.Sprintf("%s/%d", base, n)
			page.Rows = append(page.Rows, adminPostRow{Number: n, Name: html.UnescapeString(values[0]), Mail: html.UnescapeString(values[1]), Date: html.UnescapeString(values[2]), Body: html.UnescapeString(strings.ReplaceAll(values[3], "<br>", "\n")), Base: actionBase, DeleteCSRF: s.CSRF(actionBase + "/delete"), InspectCSRF: s.CSRF(actionBase + "/inspect"), RequestID: domain.NewID().String()})
		}
		if from > 1 {
			page.Previous = fmt.Sprintf("%s/%d", base, max(1, int(from)-50))
		}
		if int(from)+49 < total {
			page.Next = fmt.Sprintf("%s/%d", base, from+50)
		}
	} else {
		page.Title = "公開停止・期限終了"
		page.Message = "公開本文は表示できません。保持期限内の記録はレス番号を指定して確認できます。"
	}
	cutoff := domain.Time(1<<63 - 1)
	for _, record := range records {
		identity, err := record.Identity()
		if err != nil {
			h.failure(w, r, err)
			return
		}
		subject := ""
		if identity.Subject != (domain.Hash{}) {
			subject = identity.Subject.String()
		}
		recordBase := fmt.Sprintf("%s/%d", base, record.Post)
		page.Records = append(page.Records, adminPostRecord{Base: recordBase, CSRF: s.CSRF(recordBase + "/inspect"), RuleCSRF: s.CSRF(recordBase + "/rule"), RequestID: domain.NewID().String(), Number: record.Post, Record: record.RecordID.String(), Operation: record.Operation.String(), At: time.Unix(0, int64(record.Committed)).In(domain.JST).Format(time.RFC3339Nano), IP: identity.IP, Subject: subject, Agents: identity.Agents})
		cutoff = min(cutoff, record.Expires)
	}
	if len(records) > 0 {
		// 関連集合の先頭レスではなく、照会で指定した元番号を保持する。
		page.Selected = selected
		page.Selection = postEvidenceSelection(records)
		page.RequestID = domain.NewID().String()
		page.CSRF = s.CSRF(fmt.Sprintf("%s/%d/export", base, page.Selected))
	}
	var body bytes.Buffer
	if err := executeAdminTemplate(w, &body, adminPostsTemplate, page); err != nil {
		h.failure(w, r, err)
		return
	}
	guarded := &evidenceQueryWriter{ResponseWriter: w, check: func() error {
		h.repo.mu.Lock()
		defer h.repo.mu.Unlock()
		if err := h.repo.authorizeAdmin(s, "moderator", owner); err != nil {
			return err
		}
		if len(records) > 0 {
			if err := h.repo.authorizeEvidence(s, "evidence.manage", owner, true); err != nil {
				return err
			}
			if domain.Time(time.Now().UnixNano()) >= cutoff {
				return disclosure.ErrExpired
			}
		}
		if lease != nil {
			return lease.Check(domain.Time(time.Now().UnixNano()))
		}
		return nil
	}}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	guarded.WriteHeader(200)
	_, _ = guarded.Write(body.Bytes())
}

// prefillPostRule は認可済み原本から条件値を解決し、確認用の既存規制フォームへ渡す。
func (h *adminHandler) prefillPostRule(w http.ResponseWriter, r *http.Request, s adminauth.Session, owner domain.ID, row app.AcceptedEvidence, kind string) {
	identity, err := row.Identity()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	field, target := kind, ""
	switch {
	case kind == "ip":
		field = "auto"
		target = identity.IP
	case kind == "token" && identity.Subject != (domain.Hash{}):
		target = identity.Subject.String()
	case strings.HasPrefix(kind, "ua:"):
		n, e := strconv.Atoi(strings.TrimPrefix(kind, "ua:"))
		if e == nil && n >= 0 && n < len(identity.Agents) {
			field = "ua"
			target = identity.Agents[n]
		}
	case kind == "host":
		ip, e := netip.ParseAddr(identity.IP)
		if e == nil {
			h.repo.resolveNetworkHost(r.Context(), ip, true)
			target = h.repo.networkHosts.Hostname(ip)
		}
	}
	if target == "" {
		h.fail(w, r, 422, "RULE_TARGET_NOT_RECORDED")
		return
	}
	list, err := h.repo.adminRules(r.Context(), s, owner)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	fields := url.Values{"target": {target}, "field": {field}, "operator": {"exact"}, "effect": {"deny"}, "operation": {"both"}, "duration_minutes": {"60"}, "reason_code": {"abuse"}, "revision": {list.ETag()}, "request_id": {domain.NewID().String()}, "csrf": {s.CSRF("/api/v1/boards/" + owner.String() + "/rules")}, "extra_field": {"none"}, "extra_operator": {"exact"}}
	guarded := &evidenceQueryWriter{ResponseWriter: w, check: func() error {
		h.repo.mu.Lock()
		defer h.repo.mu.Unlock()
		if e := h.repo.authorizeAdmin(s, "board_admin", owner); e != nil {
			return e
		}
		if domain.Time(time.Now().UnixNano()) >= row.Expires {
			return disclosure.ErrExpired
		}
		return h.repo.authorizeEvidence(s, "evidence.manage", owner, true)
	}}
	h.rulesPage(guarded, 200, list, s, fields, "レスの記録から規制する値を入力しました。内容と期間を確認して登録してください。ホスト名は現在の確認結果です。", "", nil)
}

// exportPostEvidence は固定原本IDの案件を作り、既存の保全・CSV/署名ZIP取得へ接続する。
func (h *adminHandler) exportPostEvidence(w http.ResponseWriter, r *http.Request, s adminauth.Session, owner domain.ID, key uint64, rows []app.AcceptedEvidence, requestID string) {
	scope := disclosure.Scope{Board: owner, Thread: domain.U64(key), From: rows[0].Committed, To: rows[0].Committed + 1, Records: []domain.ID{}}
	for _, row := range rows {
		scope.From = min(scope.From, row.Committed)
		scope.To = max(scope.To, row.Committed+1)
		scope.Records = append(scope.Records, row.RecordID)
	}
	reason := "管理人用レス閲覧から記録を摘出"
	if _, err := h.repo.enableStorageReader(r.Context(), 38, "evidence_cases_enable"); err != nil {
		h.failure(w, r, err)
		return
	}
	h.repo.mu.Lock()
	var err error
	for _, permission := range []string{"evidence.manage"} {
		if err == nil {
			err = h.repo.authorizeEvidence(s, permission, owner, true)
		}
	}
	var c disclosure.Case
	if err == nil {
		c, err = h.repo.evidenceCases.Create(disclosure.Case{Number: "POST-" + requestID, Reason: reason, Scope: scope}, s.Admin, `"evidence:new"`, requestID, time.Now())
	}
	if err == nil {
		c, err = h.repo.evidenceCases.Get(c.ID)
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, evidenceError(err))
		return
	}
	h.extractEvidence(w, r, s, c.ID, evidenceInput{Reason: reason, Columns: []string{"connection", "content", "principal"}}, c.ETag(), requestID)
}

// postEvidenceSelection は表示時の原本集合を固定し、取得までに対象が増減したら再確認を求める。
func postEvidenceSelection(rows []app.AcceptedEvidence) string {
	ids := make([]domain.ID, len(rows))
	for i, row := range rows {
		ids[i] = row.RecordID
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return bytes.Compare(a[:], b[:]) })
	raw, _ := json.Marshal(ids)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
