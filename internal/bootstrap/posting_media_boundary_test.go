// 公開投稿の形式・本文上限・重複入力を、実HTTPと未保存の確認で検査する。
package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"strings"
	"testing"
)

// TestUnsupportedPostingTypeBeforeBody は観測器・本文・永続領域へ触れる前の形式拒否を確認する。
func TestUnsupportedPostingTypeBeforeBody(t *testing.T) {
	repo := &Repository{cfg: Config{Public: PublicConfig{BaseURL: "http://127.0.0.1:9080"}}}
	for _, path := range []string{"/test/bbs.cgi", "/web/post"} {
		for _, contentType := range []string{"multipart/form-data; boundary=test", "application/json", "application/x-www-form-urlencoded; charset=utf-16", "application/x-www-form-urlencoded, text/plain"} {
			t.Run(path+"/"+contentType, func(t *testing.T) {
				r := httptest.NewRequest("POST", "http://127.0.0.1:9080"+path, nil)
				r.Header.Set("Content-Type", contentType)
				r.Header.Set("Origin", repo.cfg.Public.BaseURL)
				body := &rejectedBody{}
				r.Body = body
				var result LegacyFormResult
				if path == "/web/post" {
					result = repo.SubmitWebRequest(r, domain.ID{1}, nil)
				} else {
					result = repo.SubmitLegacyRequest(r, domain.ID{1}, nil)
				}
				if !errors.Is(result.Err, compat.ErrCharset) || body.reads != 0 {
					t.Fatalf("error=%v, body reads=%d", result.Err, body.reads)
				}
			})
		}
	}
}

// TestPublicPostingInputBoundaries はWebの有効なCookie・CSRFを使い、入力検査そのものの拒否を確認する。
func TestPublicPostingInputBoundaries(t *testing.T) {
	cfg := testConfig(t)
	report, err := Initialize(cfg, "投稿入力境界")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	board, err := repo.CreateBoard(context.Background(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	observer, err := evidence.NewHTTPObserver(report.SiteID, domain.NewID(), "input-boundary-test")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	csrf, err := repo.IssueWebCSRF(context.Background(), board.ID, "web_create")
	if err != nil {
		t.Fatal(err)
	}
	form := "bbs=news&subject=title&MESSAGE=body&csrf=" + csrf.Token
	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	for key, value := range map[string]string{"bbs": "news", "subject": "title", "MESSAGE": "body", "csrf": csrf.Token} {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	const formType = "application/x-www-form-urlencoded; charset=UTF-8"
	cases := []struct {
		name, body string
		types      []string
		encoding   string
		status     int
	}{
		{"multipart", multipartBody.String(), []string{writer.FormDataContentType()}, "", 415},
		{"multipart_label", form, []string{writer.FormDataContentType()}, "", 415},
		{"json", `{"bbs":"news","MESSAGE":"body"}`, []string{"application/json"}, "", 415},
		{"plain", form, []string{"text/plain"}, "", 415},
		{"missing_type", form, nil, "", 403},
		{"duplicate_type", form, []string{formType, formType}, "", 403},
		{"joined_type", form, []string{formType + ", multipart/form-data"}, "", 415},
		{"unsupported_charset", form, []string{"application/x-www-form-urlencoded; charset=utf-16"}, "", 415},
		{"compressed", form, []string{formType}, "gzip", 403},
		{"duplicate_field", form + "&bbs=news", []string{formType}, "", 400},
		{"escaped_duplicate_field", form + "&%62bs=news", []string{formType}, "", 400},
		{"malformed_escape", form + "&FROM=%zz", []string{formType}, "", 400},
		{"invalid_utf8", form + "&FROM=%ff", []string{formType}, "", 400},
		{"too_many_fields", form + strings.Repeat("&extra=x", 33), []string{formType}, "", 400},
		{"oversized", form + strings.Repeat("x", 64<<10), []string{formType}, "", 413},
	}
	for _, path := range []string{"/test/bbs.cgi", "/web/post?bbs=news"} {
		t.Run(path, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					req, err := http.NewRequest("POST", server.URL+path, strings.NewReader(tc.body))
					if err != nil {
						t.Fatal(err)
					}
					req.Host = "127.0.0.1:9080"
					req.Header.Set("Origin", cfg.Public.BaseURL)
					if tc.types != nil {
						req.Header["Content-Type"] = tc.types
					}
					if tc.encoding != "" {
						req.Header.Set("Content-Encoding", tc.encoding)
					}
					req.AddCookie(csrf.Cookie)
					res, err := server.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer res.Body.Close()
					if _, err := io.Copy(io.Discard, res.Body); err != nil {
						t.Fatal(err)
					}
					if res.StatusCode != tc.status {
						t.Fatalf("status=%d, want %d", res.StatusCode, tc.status)
					}
					for _, cookie := range res.Cookies() {
						if cookie.Name == "oimo_confirm" {
							t.Fatal("invalid input reached confirmation")
						}
					}
				})
			}
		})
	}
	b := repo.posting[board.ID]
	if len(b.threads) != 0 || len(b.journals) != 0 || b.control.State().Seq != 1 {
		t.Fatal("invalid input persisted posting data")
	}
	// 同じ接続経路・Cookieで正常な入力は確認段階へ到達する。
	req, err := http.NewRequest("POST", server.URL+"/web/post?bbs=news", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:9080"
	req.Header.Set("Content-Type", formType)
	req.Header.Set("Origin", cfg.Public.BaseURL)
	req.AddCookie(csrf.Cookie)
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || !strings.Contains(string(body), "Cookieと利用規約に同意して書き込む") {
		t.Fatalf("valid input failed: status=%d", res.StatusCode)
	}
}
