// 削除依頼の受付・秘密付き照会を公開投稿と分離し、同一originとCSRFで保護する。
package bootstrap

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/webui"
)

type reportRateWindow struct {
	Minute int64
	Count  uint32
}

type reportsPage struct {
	Title, Board, CSRF, Message, Secret string
	Form                                reportForm
	IntervalMinutes                     int
	Accepted                            *deletionReport
	Lookup                              *reportLookup
}
type reportForm struct {
	Board, Thread, Ranges, Category, Reason, Contact string
}

type reportLookup struct {
	ID                    domain.ID
	Board                 domain.ID
	Thread                domain.U64
	Ranges, State, Answer string
}

var reportsTemplate = webui.Template("reports")

// writeReportsPage は出力を先に完成させ、照会秘密をcacheに残さず、外部への参照元送信を防ぐ。
func writeReportsPage(w http.ResponseWriter, status int, page reportsPage) {
	postingHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")
	var buffer bytes.Buffer
	if e := reportsTemplate.Execute(&buffer, page); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(buffer.Bytes())
}

// reportsHTTP は照会秘密をURLへ入れず、同じ404で不正ID/秘密を扱う。
func (repo *Repository) reportsHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/reports" && r.URL.Path != "/reports/lookup" || r.URL.RawQuery != "" && (r.Method != "GET" || r.URL.Path != "/reports") {
		http.NotFound(w, r)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/reports" {
		form, err := reportPrefill(r.URL.RawQuery)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		token, e := repo.reportCSRF(w, r)
		if e != nil {
			writeReportsPage(w, 503, reportsPage{Title: "削除依頼", Message: "現在受付できません。"})
			return
		}
		writeReportsPage(w, 200, reportsPage{Title: "削除依頼・照会", CSRF: token, Form: form, IntervalMinutes: repo.operations().reportIntervalMinutes()})
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !reportSameOrigin(r, repo.cfg.Public.BaseURL) {
		http.Error(w, "送信元を確認してください。", 403)
		return
	}
	names := []string{"csrf", "board", "thread", "ranges", "category", "reason", "contact"}
	lookup := r.URL.Path == "/reports/lookup"
	if lookup {
		names = []string{"csrf", "id", "secret"}
	}
	fields, e := adminForm(w, r, 64<<10, names...)
	if e != nil {
		http.Error(w, "入力を確認してください。", 400)
		return
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if e = repo.available(); e != nil {
		http.Error(w, "現在受付できません。", 503)
		return
	}
	key, e := reportKey(repo.cfg.DataDir)
	if e != nil {
		http.Error(w, "現在受付できません。", 503)
		return
	}
	defer clear(key[:])
	cookie, e := singlePostingCookie(r.Header, "oimo_reports", 43)
	if e != nil || abuse.VerifyWebCSRF(cookie, fields.Get("csrf"), "reports", key[:], 6, time.Now()) != nil {
		http.Error(w, "フォームを開き直してください。", 403)
		return
	}
	page := reportsPage{Title: "削除依頼・照会", CSRF: fields.Get("csrf"), IntervalMinutes: repo.operations().reportIntervalMinutes(), Form: reportForm{fields.Get("board"), fields.Get("thread"), fields.Get("ranges"), fields.Get("category"), fields.Get("reason"), fields.Get("contact")}}
	if e = repo.reportRate(r, lookup, key); e != nil {
		if lookup {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "間隔を空けて再照会してください。", 429)
		} else {
			writeReportRateError(w, page, e)
		}
		return
	}
	if lookup {
		id, e := parseReportID(fields.Get("id"))
		v, readErr := readReport(repo.cfg.DataDir, id, key)
		if e != nil || readErr != nil || !reportSecretMatches(v, fields.Get("secret")) || v.Expires <= domain.Time(time.Now().UnixNano()) {
			http.NotFound(w, r)
			return
		}
		writeReportsPage(w, 200, reportsPage{Title: "依頼の照会", Lookup: &reportLookup{v.ID, v.Board, v.Thread, v.Ranges, v.State, v.Answer}})
		return
	}
	v, e := repo.newReport(r, fields.Get("board"), fields.Get("thread"), fields.Get("ranges"), fields.Get("category"), fields.Get("reason"), fields.Get("contact"))
	if e != nil {
		page.Message = "入力と自サイトの対象を確認してください。"
		writeReportsPage(w, 400, page)
		return
	}
	repo.reportMu.Lock()
	defer repo.reportMu.Unlock()
	if e = repo.ensureReports(); e != nil {
		http.Error(w, "現在受付できません。", 503)
		return
	}
	ids, e := reportFiles(repo.cfg.DataDir)
	if e != nil || len(ids) >= reportLimit {
		http.Error(w, "現在受付できません。", 503)
		return
	}
	actor := reportActorHash(key, cookie)
	v.ReporterHash = &actor
	if e = repo.reportSubmissionRate(ids, v, key, time.Now()); e != nil {
		if _, limited := e.(*abuse.RateLimited); limited {
			writeReportRateError(w, page, e)
		} else {
			http.Error(w, "現在受付できません。", 503)
		}
		return
	}
	secretBytes := make([]byte, 32)
	if _, e = rand.Read(secretBytes); e != nil {
		http.Error(w, "現在受付できません。", 503)
		return
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	clear(secretBytes)
	v.LookupHash = sha256.Sum256([]byte(secret))
	if e = writeReport(repo.cfg.DataDir, v, key); e != nil {
		repo.stopped = true
		http.Error(w, "保存結果を確認できません。", 503)
		return
	}
	// 受付画面に私情報や秘密hashを渡さない。
	writeReportsPage(w, 201, reportsPage{Title: "依頼を受け付けました", Secret: secret, Accepted: &deletionReport{ID: v.ID}})
}

func reportSameOrigin(r *http.Request, base string) bool {
	raw, present, e := singleRequestHeader(r.Header, "Origin")
	if e != nil || !present {
		return false
	}
	origin, e := parseOrigin(raw)
	configured, ce := parseOrigin(base)
	return e == nil && ce == nil && normalizedOrigin(origin) == normalizedOrigin(configured)
}

// reportCSRF はサイト用途鍵と専用Cookieで、依頼の受付/照会フォームだけに使える値を発行する。
func (repo *Repository) reportCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if e := repo.available(); e != nil {
		return "", e
	}
	key, e := reportKey(repo.cfg.DataDir)
	if e != nil {
		return "", e
	}
	defer clear(key[:])
	cookie, e := singlePostingCookie(r.Header, "oimo_reports", 43)
	if e != nil {
		return "", e
	}
	now := time.Now()
	if _, e = abuse.IssueWebCSRF(cookie, "reports", key[:], 6, now); e != nil {
		secret := make([]byte, 32)
		if _, e = rand.Read(secret); e != nil {
			return "", e
		}
		cookie = base64.RawURLEncoding.EncodeToString(secret)
		clear(secret)
	}
	token, e := abuse.IssueWebCSRF(cookie, "reports", key[:], 6, now)
	if e != nil {
		return "", e
	}
	base, e := parseOrigin(repo.cfg.Public.BaseURL)
	if e != nil {
		return "", e
	}
	http.SetCookie(w, &http.Cookie{Name: "oimo_reports", Value: cookie, Path: "/reports", HttpOnly: true, Secure: base.Scheme == "https", SameSite: http.SameSiteStrictMode, MaxAge: 86400})
	return token, nil
}

// reportRate はサイトmutexの下でIPをHMAC化し、固定分窓と有界な索引で受付/照会を制限する。
func (repo *Repository) reportRate(r *http.Request, lookup bool, key [32]byte) error {
	host, _, e := net.SplitHostPort(evidence.ClientRemoteAddr(r))
	if e != nil {
		return e
	}
	ip, e := parseRateIP(host)
	if e != nil {
		return e
	}
	now := time.Now()
	minute := now.Unix() / 60
	if repo.reportRates == nil {
		repo.reportRates = map[string]reportRateWindow{}
	}
	for id, bucket := range repo.reportRates {
		if bucket.Minute < minute {
			delete(repo.reportRates, id)
		}
	}
	label, limit := "create", uint32(3)
	if lookup {
		label, limit = "lookup", 10
	}
	hash := identity.MAC(key[:], "oimo/report-rate/v1", []byte(label), []byte(ip.String())).String()
	bucket, exists := repo.reportRates[hash]
	if !exists && len(repo.reportRates) >= 8192 {
		return abuse.ErrRateCapacity
	}
	if bucket.Minute > minute {
		return abuse.ErrRateClock
	}
	if bucket.Count >= limit {
		return &abuse.RateLimited{RetryAfter: uint64(60 - now.Unix()%60)}
	}
	repo.reportRates[hash] = reportRateWindow{Minute: minute, Count: bucket.Count + 1}
	return nil
}

// newReport は現存する自サイト公開対象とレス範囲を所有列で確認し、投稿本文を含めない依頼を作る。
func (repo *Repository) newReport(r *http.Request, board, key, ranges, category, reason, contact string) (deletionReport, error) {
	var owner domain.ID
	// directoryの公開slugからだけ対象を解決する。
	if owner == (domain.ID{}) {
		dirs, e := siteDirectories(repo.site.State())
		if e != nil {
			return deletionReport{}, e
		}
		for id, b := range dirs {
			if b.Key == board && b.Status == "active" {
				owner = id
				break
			}
		}
	}
	number, e := strconv.ParseUint(key, 10, 64)
	if e != nil || number == 0 || strconv.FormatUint(number, 10) != key || owner == (domain.ID{}) {
		return deletionReport{}, ErrPostingRequest
	}
	b := repo.posting[owner]
	if b == nil {
		return deletionReport{}, ErrPostingRequest
	}
	value, e := b.worker.Submit(r.Context(), func() (any, error) {
		p := b.threads[number]
		if p == nil {
			return uint32(0), nil
		}
		snapshot := p.Snapshot(domain.Time(b.clock().UnixNano()))
		if snapshot == nil {
			return uint32(0), nil
		}
		return snapshot.PostCount, nil
	})
	if e != nil || value.(uint32) == 0 || !validReportRanges(ranges) {
		return deletionReport{}, ErrPostingRequest
	}
	parts := strings.Split(ranges, ",")
	ends := strings.Split(parts[len(parts)-1], "-")
	last, _ := strconv.ParseUint(ends[len(ends)-1], 10, 32)
	if last > uint64(value.(uint32)) {
		return deletionReport{}, ErrPostingRequest
	}
	host, _, e := net.SplitHostPort(evidence.ClientRemoteAddr(r))
	if e != nil {
		return deletionReport{}, e
	}
	ip, e := parseRateIP(host)
	if e != nil {
		return deletionReport{}, e
	}
	now := domain.Time(time.Now().UnixNano())
	v := deletionReport{ID: domain.NewID(), Board: owner, Thread: domain.U64(number), Ranges: ranges, Category: category, Reason: reason, Contact: contact, SourceIP: ip.String(), State: "open", Created: now, Expires: now + 180*86400e9, Updated: now, Revision: 1, LookupHash: domain.Hash{1}}
	return v, validateReport(v)
}

// cleanReportPending は起動時だけ未確定置換fileを消す。既存の確定fileへ昇格しない。
func (r *Repository) cleanReportPending() error {
	root := r.cfg.DataDir
	entries, e := os.ReadDir(filepath.Join(root, "reports", reportDirectory))
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pending") {
			if e := os.Remove(filepath.Join(root, "reports", reportDirectory, entry.Name())); e != nil {
				return e
			}
		}
	}
	return store.SyncDirectory(filepath.Join(root, "reports", reportDirectory))
}

// reportPrefill は自サイトの対象識別子だけを受け入れ、秘密や自由文をURLから取り込まない。
func reportPrefill(raw string) (reportForm, error) {
	form := reportForm{Category: "normal"}
	if raw == "" {
		return form, nil
	}
	if len(raw) > 1024 {
		return form, ErrPostingRequest
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) != 3 {
		return form, ErrPostingRequest
	}
	for _, name := range []string{"board", "thread", "ranges"} {
		if len(values[name]) != 1 {
			return form, ErrPostingRequest
		}
	}
	form.Board, form.Thread, form.Ranges = values.Get("board"), values.Get("thread"), values.Get("ranges")
	number, err := strconv.ParseUint(form.Thread, 10, 64)
	if !validBoardKey(form.Board) || err != nil || number == 0 || strconv.FormatUint(number, 10) != form.Thread || !validReportRanges(form.Ranges) {
		return reportForm{}, ErrPostingRequest
	}
	return form, nil
}
