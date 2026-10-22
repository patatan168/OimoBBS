// OTP登録後の片方だけの認証を拒否し、正しい二要素でのみコードを消費する。
package bootstrap

import (
	"net/http"
	"testing"
)

func TestAdminOTPTwoFactorsRequired(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("setup")
	}
	secret := enrollTestOTP(t, c)
	if c.login(adminTestSecret) != 401 {
		t.Fatal("password alone bypassed enrolled OTP")
	}
	code := otpTestCode(secret, 0)
	for _, password := range []string{""} {
		res, _ := otpPost(c, "login", map[string]string{"login": "owner", "password": password, "code": code})
		if res.StatusCode != 401 || c.cookies["oimo_admin"] != nil {
			t.Fatal("OTP alone issued session", res.StatusCode)
		}
	}
	res, _ := otpPost(c, "login", map[string]string{"login": "owner", "password": adminTestSecret, "code": code})
	if res.StatusCode != 200 {
		t.Fatal("correct pair rejected or earlier wrong password consumed code", res.StatusCode)
	}
	if c.reauth(adminTestSecret) != 403 {
		t.Fatal("password alone reauthenticated")
	}
	next := otpTestCode(secret, 1)
	res, _ = otpPost(c, "reauth", map[string]string{"password": "wrong-password", "code": next})
	if res.StatusCode != 401 {
		t.Fatal("OTP alone reauthenticated")
	}
	res, _ = otpPost(c, "reauth", map[string]string{"password": adminTestSecret, "code": next})
	if res.StatusCode != 200 {
		t.Fatal("correct pair reauth", res.StatusCode)
	}
	// 標準パスワード再認証のAPIもOTP確認を省略できない。
	res, _ = c.request("POST", "/api/v1/reauth", `{"password":"unused"}`, http.Header{"Content-Type": {"application/json"}})
	if res.StatusCode != 403 {
		t.Fatal("alternate reauthentication bypass", res.StatusCode)
	}
}
