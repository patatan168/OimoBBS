// 管理HTMLの初回byteと本文完了、および送信予約量を実HTTPで比較する。
package bootstrap

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"testing"
	"time"
)

func TestAdminResponseTiming(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	for range 3 {
		req, _ := http.NewRequest("GET", c.server.URL+"/operations", nil)
		u, _ := url.Parse(c.origin)
		req.Host = u.Host
		for _, cookie := range c.cookies {
			req.AddCookie(cookie)
		}
		start := time.Now()
		var first time.Duration
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotFirstResponseByte: func() { first = time.Since(start) }}))
		before := repo.egress.Status().Reserved
		res, err := c.server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 {
			t.Fatal(res.StatusCode, err)
		}
		timing := res.Header.Get("Server-Timing")
		spans := regexp.MustCompile(`^(?:admin;dur=([0-9]+\.[0-9]{3}), admin_reading;dur=([0-9]+\.[0-9]{3}), admin_session;dur=([0-9]+\.[0-9]{3}))$`).FindStringSubmatch(timing)
		if len(spans) != 4 {
			t.Fatal("missing response timing", timing)
		}
		total, _ := strconv.ParseFloat(spans[1], 64)
		reading, _ := strconv.ParseFloat(spans[2], 64)
		session, _ := strconv.ParseFloat(spans[3], 64)
		if reading+session > total+0.002 {
			t.Fatal("invalid timing breakdown", timing)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache policy changed")
		}
		t.Logf("TTFB=%s total=%s body=%d reserved=%d budget=%d", first, time.Since(start), len(body), repo.egress.Status().Reserved-before, repo.egress.Status().Budget)
	}
}

// timingCheckedWriter は送信予約で権限が失効する下流writerを再現する。
type timingCheckedWriter struct {
	*httptest.ResponseRecorder
	reserved bool
}

func (w *timingCheckedWriter) WriteHeaderChecked(status int, check func() error) error {
	w.reserved = true
	if err := check(); err != nil {
		return err
	}
	w.WriteHeader(status)
	return nil
}
func (w *timingCheckedWriter) WriteChecked(body []byte, check func() error) (int, error) {
	w.reserved = true
	if err := check(); err != nil {
		return 0, err
	}
	return w.Write(body)
}

func TestAdminTimingPreservesPostReservationChecks(t *testing.T) {
	for _, headerOnly := range []bool{true, false} {
		t.Run(strconv.FormatBool(headerOnly), func(t *testing.T) {
			downstream := &timingCheckedWriter{ResponseRecorder: httptest.NewRecorder()}
			timing := &adminResponseTiming{ResponseWriter: downstream, start: time.Now()}
			denied := errors.New("revoked during reservation")
			check := func() error {
				if !downstream.reserved {
					t.Fatal("checked before reservation")
				}
				return denied
			}
			var err error
			if headerOnly {
				err = timing.WriteHeaderChecked(200, check)
			} else {
				_, err = timing.WriteChecked([]byte("private evidence"), check)
			}
			if !errors.Is(err, denied) || timing.written || downstream.Body.Len() != 0 || !downstream.reserved {
				t.Fatal("revoked response was written", err)
			}
			if downstream.Header().Get("Server-Timing") == "" {
				t.Fatal("timing bytes were not included before reservation")
			}
		})
	}
}

// TestAuditResponseTiming は履歴照合・検索とHTML描画を分け、値や操作者情報を返さない。
func TestAuditResponseTiming(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	for range 2 {
		res, _ := c.request("GET", "/audit", "", nil)
		timing := res.Header.Get("Server-Timing")
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode)
		}
		for _, name := range []string{"admin_audit_query", "admin_audit_view"} {
			parts := regexp.MustCompile(name + `;dur=([0-9]+\.[0-9]{3})`).FindStringSubmatch(timing)
			if len(parts) != 2 {
				t.Fatal("missing audit timing", timing)
			}
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache policy")
		}
	}
}
