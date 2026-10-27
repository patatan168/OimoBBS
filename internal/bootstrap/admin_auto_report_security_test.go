// 自動通報原本の権限分離と、応答中のログアウト・保持期限を検査する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

// checkAutoReportPrivatePermissions は実際の成立票で、記録権限だけでは私的通報を読めないことを確認する。
func checkAutoReportPrivatePermissions(t *testing.T, owner *adminClient, repo *Repository, board domain.ID, path string) {
	t.Helper()
	for _, grant := range []bool{false, true} {
		permissions := []string{"evidence.manage"}
		login := "report-records-only"
		if grant {
			permissions = append(permissions, "private_reports.read")
			login = "report-both-permissions"
		}
		list, _ := owner.request("GET", "/api/v1/administrators", "", nil)
		input := accountInput{Login: login, Display: "通報確認担当", Password: adminTestSecret, Access: AdministratorAccess{Role: "moderator", Boards: []domain.ID{board}, Permissions: permissions, Enabled: true}}
		res, account, body := owner.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
		if res.StatusCode != 200 {
			t.Fatal("create restricted administrator", res.StatusCode, body)
		}
		client := newAdminClient(t, repo)
		t.Cleanup(client.server.Close)
		raw, session, err := repo.adminAuth.Create(account.ID, account.Generation, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		raw, session, err = repo.adminAuth.MarkReauthenticated(raw, session, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		client.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: raw}
		res, _ = client.request("GET", "/api/v1/reports", "", nil)
		if (res.StatusCode == 200) != grant {
			t.Fatal("direct private report permission", res.StatusCode)
		}
		fields := url.Values{"csrf": {session.CSRF(path + "/inspect")}, "request_id": {domain.NewID().String()}}
		res, body = client.request("POST", path+"/inspect", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 200 || strings.Contains(body, "PRIVATE-REVIEW-REASON") != grant || !strings.Contains(body, "PUBLIC-REVIEW-REASON-1") {
			t.Fatal("private reason permission boundary", grant, res.StatusCode)
		}
	}
}

// checkAutoReportSendLogout はヘッダー確定時の失効で、取得済み原本の本文送信も中断することを確認する。
func checkAutoReportSendLogout(t *testing.T, owner *adminClient, repo *Repository, board domain.ID, path string) {
	t.Helper()
	session, err := repo.adminAuth.Lookup(owner.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, isolated, err := repo.adminAuth.Create(session.Admin, session.Generation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, isolated, err = repo.adminAuth.MarkReauthenticated(raw, isolated, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	fields := url.Values{"csrf": {isolated.CSRF(path + "/inspect")}, "request_id": {domain.NewID().String()}}
	req := httptest.NewRequest("POST", owner.origin+path+"/inspect", strings.NewReader(fields.Encode()))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Origin", owner.origin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "oimo_admin", Value: raw})
	recorder := httptest.NewRecorder()
	writer := &logoutReportWriter{recorder, func() { repo.adminAuth.Delete(raw) }}
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("private auto-report send must abort after logout")
			}
		}()
		server.Handler.ServeHTTP(writer, req)
	}()
	if recorder.Body.Len() != 0 {
		t.Fatal("private auto-report sent after logout")
	}
	h := &adminHandler{repo: repo}
	for _, expired := range []bool{true, false} {
		until := domain.Time(time.Now().Add(time.Hour).UnixNano())
		if expired {
			until = domain.Time(time.Now().Add(-time.Second).UnixNano())
		}
		w := httptest.NewRecorder()
		guard := h.checkedAutoReportWriter(w, session, board, []autoReportContent{{until: until}}).(*adminCheckedWriter)
		if (guard.check() != nil) != expired {
			t.Fatal("original expiry check", expired)
		}
	}
}
