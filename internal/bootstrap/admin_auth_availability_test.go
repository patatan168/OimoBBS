// 未認証の画面要求・誤ったパスワードが別接続元の管理認証を締め出さないことを検証する。
package bootstrap

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/waf"
	"os"
	"testing"
	"time"
)

func TestAdminOTPWrongPasswordCannotLockOtherSource(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	owner := newAdminClient(t, repo)
	defer owner.server.Close()
	if owner.login(adminTestSecret) != 303 || owner.reauth(adminTestSecret) != 200 {
		t.Fatal("setup")
	}
	secret := enrollTestOTP(t, owner)
	attacker := newAdminClient(t, repo)
	defer attacker.server.Close()
	for range 4 {
		res, _ := otpPost(attacker, "login", map[string]string{"login": "owner", "password": "wrong-password", "code": "000000"})
		if res.StatusCode != 401 {
			t.Fatal("unexpected wrong-password result", res.StatusCode)
		}
	}
	victim := newAdminClient(t, repo)
	defer victim.server.Close()
	victim.server.Client().Transport = &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).DialContext}
	defer victim.server.Client().CloseIdleConnections()
	res, _ := otpPost(victim, "login", map[string]string{"login": "owner", "password": adminTestSecret, "code": otpTestCode(secret, 0)})
	if res.StatusCode != 200 {
		t.Fatal("unrelated source with both factors locked out", res.StatusCode)
	}
}

func TestAdminOTPVerifiedPasswordStillLimitsCodeGuesses(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	owner := newAdminClient(t, repo)
	defer owner.server.Close()
	if owner.login(adminTestSecret) != 303 || owner.reauth(adminTestSecret) != 200 {
		t.Fatal("setup")
	}
	enrollTestOTP(t, owner)
	for i := 0; i < 5; i++ {
		person := newAdminClient(t, repo)
		person.server.Client().Transport = &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("127.0.0.%d", 10+i))}}).DialContext}
		res, _ := otpPost(person, "login", map[string]string{"login": "owner", "password": adminTestSecret, "code": "invalid"})
		person.server.Client().CloseIdleConnections()
		person.server.Close()
		want := 401
		if i == 4 {
			want = 429
		} // 登録確認もアカウントの5件枠を一度消費している。
		if res.StatusCode != want {
			t.Fatal("account-wide OTP guessing limit changed", i, res.StatusCode)
		}
	}
}

// TestAdminLoginFormsUnderAnonymousFlood は明示した時だけ50秒の並走試験を行う。
func TestAdminLoginFormsUnderAnonymousFlood(t *testing.T) {
	if os.Getenv("OIMO_AUTH_AVAILABILITY_PROBE") != "1" {
		t.Skip("50秒の隔離HTTP並走試験は未指定")
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	owner := newAdminClient(t, repo)
	defer owner.server.Close()
	if owner.login(adminTestSecret) != 303 || owner.reauth(adminTestSecret) != 200 {
		t.Fatal("setup")
	}
	secret := enrollTestOTP(t, owner)
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	server, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	victim := newAdminClient(t, repo)
	defer victim.server.Close()
	victim.server.Client().Transport = &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.254")}}).DialContext}
	defer victim.server.Client().CloseIdleConnections()
	start := time.Now()
	for i := 0; i < 10000; i++ {
		time.Sleep(time.Until(start.Add(time.Duration(i) * 5 * time.Millisecond)))
		req := httptest.NewRequest("GET", repo.cfg.Admin.Origin+"/login", nil)
		req.RemoteAddr = fmt.Sprintf("127.0.0.%d:12345", 2+i%8)
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatal("anonymous page", i, w.Code)
		}
		switch i {
		case 2500:
			res, _ := otpPost(victim, "login", map[string]string{"login": "owner", "password": adminTestSecret, "code": otpTestCode(secret, 0)})
			if res.StatusCode != 200 {
				t.Fatal("genuine OTP login during flood", res.StatusCode)
			}
		case 5000:
			res, _ := otpPost(victim, "reauth", map[string]string{"password": adminTestSecret, "code": otpTestCode(secret, 1)})
			if res.StatusCode != 200 {
				t.Fatal("genuine reauthentication during flood", res.StatusCode)
			}
		case 7500:
			res, _ := victim.request("GET", "/api/v1/site", "", nil)
			if res.StatusCode != 200 {
				t.Fatal("authenticated access during flood", res.StatusCode)
			}
		}
	}
	res, _ := victim.request("GET", "/login", "", nil)
	if res.StatusCode != 200 {
		t.Fatal("new login unavailable after flood", res.StatusCode)
	}
	t.Logf("PASS: WAF ON, 10000 anonymous page requests in %s; genuine password+OTP login, reauthentication and authenticated read succeeded during requests", time.Since(start))
}

func TestAdminPasswordFailuresDoNotLockOtherSource(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	attacker := newAdminClient(t, repo)
	defer attacker.server.Close()
	for range 5 {
		if code := attacker.login("wrong-password"); code != 401 {
			t.Fatal("unexpected invalid-password response", code)
		}
		time.Sleep(time.Second)
	}
	victim := newAdminClient(t, repo)
	defer victim.server.Close()
	victim.server.Client().Transport = &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).DialContext}
	defer victim.server.Client().CloseIdleConnections()
	if code := victim.login(adminTestSecret); code != 303 {
		t.Fatal("valid login blocked", code)
	}
	if err := repo.adminAuth.AttemptPasskey("127.0.0.2", time.Now()); err != nil {
		t.Fatal("passkey also blocked", err)
	}
}
func TestAdminPasswordFailuresDoNotBlockReauthentication(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	victim := newAdminClient(t, repo)
	defer victim.server.Close()
	victim.server.Client().Transport = &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).DialContext}
	defer victim.server.Client().CloseIdleConnections()
	if victim.login(adminTestSecret) != 303 {
		t.Fatal("initial login")
	}
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	attacker := newAdminClient(t, repo)
	defer attacker.server.Close()
	for range 4 {
		if code := attacker.login("wrong-password"); code != 401 {
			t.Fatal("unexpected invalid-password response", code)
		}
		time.Sleep(time.Second)
	}
	if code := victim.reauth(adminTestSecret); code != 200 {
		t.Fatal("valid reauthentication blocked", code)
	}
}
