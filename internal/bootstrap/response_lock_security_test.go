// 実HTTPの応答送信を停止し、匿名要求がサイト共通mutexを占有しないことを検査する。
package bootstrap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// responseLockProbe は最初の応答確定で所有mutexを調べ、送信待機を明示的なゲートで再現する。
type responseLockProbe struct {
	http.ResponseWriter
	mutex     *sync.RWMutex
	available chan<- bool
	release   <-chan struct{}
	once      sync.Once
}

func (w *responseLockProbe) WriteHeader(status int) {
	w.once.Do(func() {
		available := w.mutex.TryLock()
		if available {
			w.mutex.Unlock()
		}
		w.available <- available
		<-w.release
	})
	w.ResponseWriter.WriteHeader(status)
}

// TestPublicReportResponseReleasesSiteMutex は成功・入力拒否・照会・頻度拒否の応答で共通mutexを解放する。
func TestPublicReportResponseReleasesSiteMutex(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		status     int
	}{
		{"csrf", "/reports", 403},
		{"invalid-target", "/reports", 400},
		{"accepted", "/reports", 201},
		{"cooldown", "/reports", 429},
		{"missing-lookup", "/reports/lookup", 404},
		{"lookup", "/reports/lookup", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, repo, c, _, thread := reportTestSetup(t)
			defer repo.Close()
			defer c.server.Close()
			fields := url.Values{"csrf": {c.token}, "board": {"reports"}, "thread": {thread}, "ranges": {"1"}, "category": {"normal"}, "reason": {"送信境界の検査"}, "contact": {""}}
			if tc.name == "csrf" {
				fields.Set("csrf", "invalid")
			}
			if tc.name == "invalid-target" {
				fields.Set("board", "missing")
			}
			var id domain.ID
			secret := strings.Repeat("A", 43)
			if tc.name == "cooldown" || tc.name == "lookup" {
				id, secret = createTestReport(t, c, thread)
			}
			if tc.path == "/reports/lookup" {
				if id == (domain.ID{}) {
					id = domain.NewID()
				}
				fields = url.Values{"csrf": {c.token}, "id": {id.String()}, "secret": {secret}}
			}
			repo.mu.Lock()
			site := siteID(repo.site.State())
			repo.mu.Unlock()
			observer, err := evidence.NewHTTPObserver(site, domain.NewID(), "report-lock-test")
			if err != nil {
				t.Fatal(err)
			}
			available := make(chan bool, 1)
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			public := repo.SiteWebHandler(observer)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				public.ServeHTTP(&responseLockProbe{ResponseWriter: w, mutex: &repo.mu, available: available, release: release}, r)
			}))
			server.Config.ConnContext = observer.ConnContext
			server.Start()
			defer server.Close()
			defer unblock()
			req, err := http.NewRequestWithContext(t.Context(), "POST", server.URL+tc.path, strings.NewReader(fields.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			origin, _ := url.Parse(cfg.Public.BaseURL)
			req.Host = origin.Host
			req.Header.Set("Origin", cfg.Public.BaseURL)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(c.cookie)
			type result struct {
				status int
				err    error
			}
			done := make(chan result, 1)
			go func() {
				res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				if err != nil {
					done <- result{err: err}
					return
				}
				_, err = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				done <- result{status: res.StatusCode, err: err}
			}()
			select {
			case free := <-available:
				if !free {
					t.Error("response transmission holds the site mutex")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("response gate not reached")
			}
			unblock()
			got := <-done
			if got.err != nil || got.status != tc.status {
				t.Fatalf("HTTP result: status=%d want=%d err=%v", got.status, tc.status, got.err)
			}
		})
	}
}

// TestEvidenceAPIResponseReleasesSiteMutex は認証済みの提出用記録APIも送信前に共通mutexを解放する。
func TestEvidenceAPIResponseReleasesSiteMutex(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("fixture authentication")
	}
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	available := make(chan bool, 1)
	release := make(chan struct{})
	close(release)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admin.Handler.ServeHTTP(&responseLockProbe{ResponseWriter: w, mutex: &repo.mu, available: available, release: release}, r)
	}))
	defer server.Close()
	req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/api/v1/evidence/cases", nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse(cfg.Admin.Origin)
	req.Host = origin.Host
	req.Header.Set("Accept-Encoding", "gzip;q=0.1")
	req.AddCookie(c.cookies["oimo_admin"])
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	_, err = io.Copy(io.Discard, res.Body)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("HTTP control: status=%d err=%v", res.StatusCode, err)
	}
	if !<-available {
		t.Error("evidence API transmission holds the site mutex")
	}
}

// evidenceResponseWait は帯域予約の完了時点で認可を変更し、渡された送信直前検査を実行する。
type evidenceResponseWait struct {
	*httptest.ResponseRecorder
	onHeaders, onBody func()
}

func (w *evidenceResponseWait) WriteHeaderChecked(status int, check func() error) error {
	if w.onHeaders != nil {
		w.onHeaders()
		w.onHeaders = nil
	}
	if err := check(); err != nil {
		return err
	}
	w.WriteHeader(status)
	return nil
}

func (w *evidenceResponseWait) WriteChecked(raw []byte, check func() error) (int, error) {
	if w.onBody != nil {
		w.onBody()
		w.onBody = nil
	}
	if err := check(); err != nil {
		return 0, err
	}
	return w.Write(raw)
}

// TestEvidenceAPIResponseRechecksAuthorization はmutex解放後の帯域待機中に失効した案件情報を送らない。
func TestEvidenceAPIResponseRechecksAuthorization(t *testing.T) {
	for _, headers := range []bool{true, false} {
		for _, changeScope := range []bool{false, true} {
			name := "logout"
			if changeScope {
				name = "scope-change"
			}
			if headers {
				name += "/headers"
			} else {
				name += "/body"
			}
			t.Run(name, func(t *testing.T) {
				repo, c, outside := evidenceListFixture(t)
				raw := c.cookies["oimo_admin"].Value
				session, err := repo.adminAuth.Lookup(raw, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				changed := false
				invalidate := func() {
					changed = true
					if !changeScope {
						repo.adminAuth.Delete(raw)
						return
					}
					_, err := repo.SetAdministratorAccess("case.reader", AdministratorAccess{Role: "board_admin", Boards: []domain.ID{outside.Scope.Board}, Permissions: []string{"evidence.manage"}, Enabled: true})
					if err != nil {
						t.Fatal(err)
					}
				}
				recorder := httptest.NewRecorder()
				writer := &evidenceResponseWait{ResponseRecorder: recorder}
				if headers {
					writer.onHeaders = invalidate
				} else {
					writer.onBody = invalidate
				}
				h := &adminHandler{repo: repo, auth: repo.adminAuth}
				req := httptest.NewRequest("GET", c.origin+"/api/v1/evidence/cases", nil)
				func() {
					defer func() {
						if got := recover(); got != http.ErrAbortHandler {
							t.Errorf("expired API send was not aborted: %v", got)
						}
					}()
					h.evidenceGET(writer, req, session, "/evidence/cases", true)
				}()
				if !changed || recorder.Body.Len() != 0 {
					t.Fatal("private case response escaped authorization change", changed, recorder.Body.Len())
				}
			})
		}
	}
}
