// 生フォームを実HTTPから永続化し、採番・秘密除去・再起動時の再送を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/textcodec"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type formResult struct {
	Key          uint64
	Number       uint32
	Duplicate    bool
	Accepted     bool
	Confirmation *ConfirmationChallenge
}

// anonymousOnlyJar は匿名Cookieだけを保存し、確認Cookieの明示的な試験操作を維持する。
type anonymousOnlyJar struct{ http.CookieJar }

func (j anonymousOnlyJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	for _, cookie := range cookies {
		if cookie.Name == "oimo_anon" {
			j.CookieJar.SetCookies(u, []*http.Cookie{cookie})
		}
	}
}

func formServer(t *testing.T, repo *Repository, site, owner domain.ID, keepAnonymous ...bool) *httptest.Server {
	t.Helper()
	if len(keepAnonymous) == 0 {
		keepAnonymous = []bool{true}
	}
	observer, e := evidence.NewHTTPObserver(site, domain.NewID(), "form-integration-test")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result LegacyFormResult
		if r.URL.Path == "/web/post" {
			result = repo.SubmitWebRequest(r, owner, observer)
		} else {
			result = repo.SubmitLegacyRequest(r, owner, observer)
		}
		if len(keepAnonymous) > 0 && keepAnonymous[0] && result.AnonymousCookie != nil {
			http.SetCookie(w, result.AnonymousCookie)
		}
		if result.Confirmation != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.SetCookie(w, &http.Cookie{Name: "oimo_confirm", Value: result.Confirmation.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
		if result.Status != store.Durable && result.Confirmation == nil {
			w.WriteHeader(400)
		}
		json.NewEncoder(w).Encode(formResult{result.ThreadKey, result.PostNumber, result.Duplicate, result.Status == store.Durable, result.Confirmation})
	}))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	if len(keepAnonymous) > 0 && keepAnonymous[0] {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		server.Client().Jar = anonymousOnlyJar{jar}
	}
	return server
}

// sendForm は試験利用者が確認画面を承認する二往復。確認境界の試験はOnceを使う。
func sendForm(server *httptest.Server, fields url.Values) (formResult, error) {
	result, e := sendFormOnce(server, fields, "")
	if e != nil || result.Confirmation == nil {
		return result, e
	}
	return sendFormOnce(server, fields, result.Confirmation.Token)
}
func sendFormOnce(server *httptest.Server, fields url.Values, token string) (formResult, error) {
	request, e := http.NewRequest("POST", server.URL+"/test/bbs.cgi", strings.NewReader(fields.Encode()))
	if e != nil {
		return formResult{}, e
	}
	request.Host = "127.0.0.1:9080"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	if token != "" {
		request.AddCookie(&http.Cookie{Name: "oimo_confirm", Value: token})
	}
	response, e := server.Client().Do(request)
	if e != nil {
		return formResult{}, e
	}
	defer response.Body.Close()
	var result formResult
	e = json.NewDecoder(response.Body).Decode(&result)
	if result.Confirmation != nil {
		for _, cookie := range response.Cookies() {
			if cookie.Name == "oimo_confirm" {
				result.Confirmation.Token = cookie.Value
			}
		}
	}
	return result, e
}
func TestLegacyFormDurableRoundTrip(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprint("parallel=", concurrent), func(t *testing.T) { testLegacyFormDurableRoundTrip(t, concurrent) })
	}
}
func testLegacyFormDurableRoundTrip(t *testing.T, concurrent bool) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "フォーム試験")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate, PostingOptions{ParallelCaptureValidation: concurrent})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { repo.Close() }()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, repo, report.SiteID, info.ID)
	defer func() { server.Close() }()
	create := url.Values{"bbs": {"news"}, "subject": {"題😀"}, "FROM": {"名前&#35;表示#private-trip-secret"}, "MESSAGE": {"<script>\r\n最初の本文"}, "unknown": {"unknown-private-secret"}, "oimo_request_id": {"request-create-0001"}}
	first, e := sendForm(server, create)
	if e != nil || !first.Accepted || first.Key == 0 || first.Number != 1 {
		t.Fatal(first, e)
	}
	retry, e := sendForm(server, create)
	if e != nil || !retry.Duplicate || retry.Key != first.Key {
		t.Fatal(retry, e)
	}
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(first.Key)}, "mail": {"sage"}, "MESSAGE": {"二番目"}, "oimo_request_id": {"request-reply-00001"}}
	second, e := sendForm(server, reply)
	if e != nil || !second.Accepted || second.Number != 2 {
		t.Fatal(second, e)
	}
	for _, invalid := range []url.Values{
		{"bbs": {"news"}, "subject": {"別題"}, "MESSAGE": {"別スレ"}, "oimo_request_id": {"request-reply-00001"}},
		{"bbs": {"news"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"返信"}, "oimo_request_id": {"request-create-0001"}},
		{"bbs": {"wrong"}, "subject": {"題"}, "MESSAGE": {"本文"}},
		{"bbs": {"news"}, "subject": {"題"}, "MESSAGE": {"本文"}, "mail": {"sage #cap:id:cap-private-secret"}},
		{"bbs": {"news"}, "subject": {"題"}, "MESSAGE": {"!status:"}},
	} {
		result, e := sendForm(server, invalid)
		if e != nil || result.Accepted {
			t.Fatal("invalid accepted", result, e)
		}
	}
	const count = 8
	var wg sync.WaitGroup
	results := make(chan formResult, count)
	errs := make(chan error, count)
	for n := 0; n < count; n++ {
		wg.Go(func() {
			r, e := sendForm(server, url.Values{"bbs": {"news"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {fmt.Sprintf("並行返信%d", n)}})
			results <- r
			errs <- e
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	seen := map[uint32]bool{}
	for r := range results {
		if !r.Accepted || r.Duplicate || r.Number < 3 || r.Number > count+2 || seen[r.Number] {
			t.Fatal(r)
		}
		seen[r.Number] = true
	}
	snapshot, e := repo.Thread(context.Background(), info.ID, first.Key)
	if e != nil || snapshot == nil || snapshot.PostCount != count+2 {
		t.Fatal(snapshot, e)
	}
	dat, e := textcodec.Decode(snapshot.DAT)
	if e != nil || !strings.Contains(dat, "&lt;script&gt;<br>最初の本文") || !strings.Contains(dat, "名前#表示 ◆") {
		t.Fatal(dat, e)
	}
	checkStoredFormCaptures(t, repo, info.ID)
	server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	// 秘密はthread WALにも署名proposalにも残さない。
	e = filepath.WalkDir(cfg.DataDir, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		for _, secret := range []string{"private-trip-secret", "unknown-private-secret", "request-create-0001", "request-reply-00001", "cap-private-secret"} {
			if strings.Contains(string(raw), secret) {
				return fmt.Errorf("secret persisted in %s", path)
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate, PostingOptions{ParallelCaptureValidation: concurrent})
	if e != nil {
		t.Fatal(e)
	}
	server = formServer(t, repo, report.SiteID, info.ID)
	for _, fields := range []url.Values{create, reply} {
		r, e := sendForm(server, fields)
		if e != nil || !r.Accepted || !r.Duplicate || r.Key != first.Key {
			t.Fatal(r, e)
		}
	}
	restored, e := repo.Thread(context.Background(), info.ID, first.Key)
	if e != nil || restored == nil || string(restored.DAT) != string(snapshot.DAT) {
		t.Fatal("restored snapshot differs", e)
	}
	// フォーム経路だけで観測した失効も、時計逆行で取り消さない。
	b := repo.posting[info.ID]
	realNow := time.Now()
	for _, clockTime := range []time.Time{time.Unix(0, int64(restored.Expires)), realNow} {
		_, e = b.worker.Submit(context.Background(), func() (any, error) { b.clock = func() time.Time { return clockTime }; return nil, nil })
		if e != nil {
			t.Fatal(e)
		}
		result, e := sendForm(server, reply)
		if e != nil || result.Accepted {
			t.Fatal("expired form resurrected", result, e)
		}
	}

}
