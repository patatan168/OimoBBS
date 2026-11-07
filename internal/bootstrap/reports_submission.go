// 削除依頼の確定処理を応答送信から分け、低速な送信で共通mutexを保持しない。
package bootstrap

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
)

type reportSubmissionReply struct {
	status, retryAfter int
	message            string
	page               *reportsPage
	rate               error
}

// write は全ての保存mutexを解放した後に、正常・拒否・照会の応答を送信する。
func (v reportSubmissionReply) write(w http.ResponseWriter, r *http.Request) {
	if v.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(v.retryAfter))
	}
	switch {
	case v.rate != nil:
		writeReportRateError(w, *v.page, v.rate)
	case v.page != nil:
		writeReportsPage(w, v.status, *v.page)
	case v.status == 404:
		http.NotFound(w, r)
	default:
		http.Error(w, v.message, v.status)
	}
}

// prepareReportSubmission はCSRF・頻度・保存を直列化し、HTTP writerを持たない返却値へ結果を固定する。
func (repo *Repository) prepareReportSubmission(r *http.Request, fields url.Values, lookup bool) reportSubmissionReply {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.available() != nil {
		return reportSubmissionReply{status: 503, message: "現在受付できません。"}
	}
	key, e := reportKey(repo.cfg.DataDir)
	if e != nil {
		return reportSubmissionReply{status: 503, message: "現在受付できません。"}
	}
	defer clear(key[:])
	cookie, e := singlePostingCookie(r.Header, "oimo_reports", 43)
	if e != nil || abuse.VerifyWebCSRF(cookie, fields.Get("csrf"), "reports", key[:], 6, time.Now()) != nil {
		return reportSubmissionReply{status: 403, message: "フォームを開き直してください。"}
	}
	page := reportsPage{Title: "削除依頼・照会", CSRF: fields.Get("csrf"), IntervalMinutes: repo.operations().reportIntervalMinutes(), Form: reportForm{fields.Get("board"), fields.Get("thread"), fields.Get("ranges"), fields.Get("category"), fields.Get("reason"), fields.Get("contact")}}
	if e = repo.reportRate(r, lookup, key); e != nil {
		if lookup {
			return reportSubmissionReply{status: 429, retryAfter: 60, message: "間隔を空けて再照会してください。"}
		}
		return reportSubmissionReply{page: &page, rate: e}
	}
	if lookup {
		id, e := parseReportID(fields.Get("id"))
		v, readErr := readReport(repo.cfg.DataDir, id, key)
		if e != nil || readErr != nil || !reportSecretMatches(v, fields.Get("secret")) || v.Expires <= domain.Time(time.Now().UnixNano()) {
			return reportSubmissionReply{status: 404}
		}
		return reportSubmissionReply{status: 200, page: &reportsPage{Title: "依頼の照会", Lookup: &reportLookup{v.ID, v.Board, v.Thread, v.Ranges, v.State, v.Answer}}}
	}
	v, e := repo.newReport(r, fields.Get("board"), fields.Get("thread"), fields.Get("ranges"), fields.Get("category"), fields.Get("reason"), fields.Get("contact"))
	if e != nil {
		page.Message = "入力と自サイトの対象を確認してください。"
		return reportSubmissionReply{status: 400, page: &page}
	}
	repo.reportMu.Lock()
	defer repo.reportMu.Unlock()
	if repo.ensureReports() != nil {
		return reportSubmissionReply{status: 503, message: "現在受付できません。"}
	}
	ids, e := reportFiles(repo.cfg.DataDir)
	if e != nil || len(ids) >= reportLimit {
		return reportSubmissionReply{status: 503, message: "現在受付できません。"}
	}
	actor := reportActorHash(key, cookie)
	v.ReporterHash = &actor
	if e = repo.reportSubmissionRate(ids, v, key, time.Now()); e != nil {
		if _, limited := e.(*abuse.RateLimited); limited {
			return reportSubmissionReply{page: &page, rate: e}
		}
		return reportSubmissionReply{status: 503, message: "現在受付できません。"}
	}
	secretBytes := make([]byte, 32)
	if _, e = rand.Read(secretBytes); e != nil {
		return reportSubmissionReply{status: 503, message: "現在受付できません。"}
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	clear(secretBytes)
	v.LookupHash = sha256.Sum256([]byte(secret))
	if e = writeReport(repo.cfg.DataDir, v, key); e != nil {
		repo.stopped = true
		return reportSubmissionReply{status: 503, message: "保存結果を確認できません。"}
	}
	// 受付画面に私情報や秘密hashを渡さない。
	return reportSubmissionReply{status: 201, page: &reportsPage{Title: "依頼を受け付けました", Secret: secret, Accepted: &deletionReport{ID: v.ID}}}
}
