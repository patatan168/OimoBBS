// OTPのHTTP登録・使い回し拒否・暗号文の束縛・パスワード禁止・CLI復旧を検証する。
package bootstrap

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

var otpCSRFPattern = regexp.MustCompile(`data-otp-manager data-csrf="([A-Za-z0-9_-]+)"`)

// otpTestCode は認証アプリ側として共有鍵からコードを作る。RFCベクトルの検査はadminauth側で行う。
func otpTestCode(secret []byte, delta int64) string {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(time.Now().Unix()/30+delta))
	h := hmac.New(sha1.New, secret)
	h.Write(raw[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

func otpPost(c *adminClient, kind string, in any) (*http.Response, string) {
	c.t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		c.t.Fatal(err)
	}
	csrf := ""
	if kind == "login" {
		_, page := c.request("GET", "/login", "", nil)
		csrf = pageFields(page).Get("csrf")
	} else if cookie := c.cookies["oimo_admin"]; cookie != nil {
		// GETページから本人専用のCSRFを取り出す。秘密や保存状態は参照しない。
		_, page := c.request("GET", "/passkeys", "", nil)
		matched := otpCSRFPattern.FindStringSubmatch(page)
		if len(matched) > 1 {
			csrf = matched[1]
		}
	}
	return c.request("POST", otpRoute+kind, string(data), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {csrf}})
}

func enrollTestOTP(t *testing.T, c *adminClient) []byte {
	t.Helper()
	res, body := otpPost(c, "register/begin", struct{}{})
	if res.StatusCode != 200 {
		t.Fatalf("begin status %d", res.StatusCode)
	}
	var setup struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	if json.Unmarshal([]byte(body), &setup) != nil || setup.Secret == "" {
		t.Fatal("missing setup")
	}

	qrResponse, qrBody := c.request("GET", otpRoute+"register/qr", "", nil)
	if qrResponse.StatusCode != 200 || qrResponse.Header.Get("Content-Type") != "image/png" || !strings.Contains(qrResponse.Header.Get("Cache-Control"), "no-store") {
		t.Fatal("QR headers", qrResponse.StatusCode)
	}
	if _, err := png.Decode(strings.NewReader(qrBody)); err != nil {
		t.Fatal("QR is not PNG", err)
	}
	savedSession := c.cookies["oimo_admin"]
	delete(c.cookies, "oimo_admin")
	if denied, _ := c.request("GET", otpRoute+"register/qr", "", nil); denied.StatusCode != 401 {
		t.Fatal("QR accessible without session", denied.StatusCode)
	}
	c.cookies["oimo_admin"] = savedSession
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	res, _ = otpPost(c, "register/finish", map[string]string{"code": otpTestCode(secret, -1)})
	if res.StatusCode != 200 {
		t.Fatal("enrollment failed", res.StatusCode)
	}
	if expired, _ := c.request("GET", otpRoute+"register/qr", "", nil); expired.StatusCode != 401 {
		t.Fatal("QR accessible after enrollment", expired.StatusCode)
	}
	return secret
}

func TestAdminOTPEnrollmentPolicyAndOfflineRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	cfg = repo.cfg
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("password login")
	}
	initial := *c.cookies["oimo_admin"]
	secret := enrollTestOTP(t, c)
	c.cookies["oimo_admin"] = &initial
	if res, _ := c.request("GET", "/api/v1/site", "", nil); res.StatusCode != 401 {
		t.Fatal("enrollment retained old session")
	}
	delete(c.cookies, "oimo_admin")
	loginCode := otpTestCode(secret, 0)
	res, _ := otpPost(c, "login", map[string]string{"login": "owner", "password": adminTestSecret, "code": loginCode})
	if res.StatusCode != 200 {
		t.Fatal("otp login", res.StatusCode)
	}
	res, _ = otpPost(c, "reauth", map[string]string{"password": adminTestSecret, "code": loginCode})
	if res.StatusCode != 401 {
		t.Fatal("replayed OTP accepted", res.StatusCode)
	}
	res, _ = otpPost(c, "reauth", map[string]string{"password": adminTestSecret, "code": otpTestCode(secret, 1)})
	if res.StatusCode != 200 {
		t.Fatal("otp reauthentication", res.StatusCode)
	}
	res, _ = otpPost(c, "policy", map[string]bool{"password_disabled": true})
	if res.StatusCode != 200 {
		t.Fatal("policy", res.StatusCode)
	}
	if c.login(adminTestSecret) != 401 {
		t.Fatal("password bypassed policy")
	}
	repo.mu.Lock()
	accounts, err := repo.administrators()
	if err != nil {
		t.Fatal(err)
	}
	a := accounts[0]
	security, _, err := repo.adminSecurityLocked(a)
	if err != nil || !security.PasswordDisabled || bytes.Contains(repo.site.State().Rows["admin_security:"+a.ID.String()].Value, secret) {
		t.Fatal("OTP state")
	}
	plain, err := repo.openOTP(a, security.OTPSealed)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatal("decryption")
	}
	clear(plain)
	other := a
	other.ID = domain.NewID()
	if _, err := repo.openOTP(other, security.OTPSealed); err == nil {
		t.Fatal("ciphertext transferable")
	}
	tampered := append([]byte{}, security.OTPSealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := repo.openOTP(a, tampered); err == nil {
		t.Fatal("ciphertext tampering accepted")
	}
	raw, s, err := repo.adminAuth.Create(a.ID, a.Generation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, s, err = repo.adminAuth.MarkStronglyReauthenticated(raw, s, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Unlock()
	c.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: raw}
	if c.reauth(adminTestSecret) != 403 {
		t.Fatal("password reauth bypassed policy")
	}
	res, _ = otpPost(c, "remove", struct{}{})
	if res.StatusCode != 409 {
		t.Fatal("last OTP removed", res.StatusCode)
	}
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	if _, err := repo.ConfigureAdministrator("owner", "所有者", "offline-recovered-password-only", true); err != nil {
		t.Fatal("offline reset", err)
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c = newAdminClient(t, repo)
	defer c.server.Close()
	if c.login("offline-recovered-password-only") != 303 {
		t.Fatal("offline recovery login")
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	accounts, _ = repo.administrators()
	security, _, err = repo.adminSecurityLocked(accounts[0])
	if err != nil || security.PasswordDisabled || len(security.OTPSealed) != 0 || security.PasswordChangeRequired {
		t.Fatal("offline recovery did not clear policy and OTP")
	}
}

func TestAdminOTPConcurrentUseAndRestart(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	cfg = repo.cfg
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	secret := enrollTestOTP(t, c)
	clients := []*adminClient{newAdminClient(t, repo), newAdminClient(t, repo)}
	defer clients[0].server.Close()
	defer clients[1].server.Close()
	code := otpTestCode(secret, 0)
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for _, client := range clients {
		wg.Add(1)
		go func(c *adminClient) {
			defer wg.Done()
			res, _ := otpPost(c, "login", map[string]string{"login": "owner", "password": adminTestSecret, "code": code})
			codes <- res.StatusCode
		}(client)
	}
	wg.Wait()
	close(codes)
	success, failed := 0, 0
	for status := range codes {
		if status == 200 {
			success++
		} else if status == 401 {
			failed++
		}
	}
	if success != 1 || failed != 1 {
		t.Fatal("OTP was not consumed atomically", success, failed)
	}
	c.server.Close()
	clients[0].server.Close()
	clients[1].server.Close()
	repo.Close()
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c = newAdminClient(t, repo)
	defer c.server.Close()
	res, _ := otpPost(c, "login", map[string]string{"login": "owner", "password": adminTestSecret, "code": code})
	if res.StatusCode != 401 {
		t.Fatal("OTP replay survived restart", res.StatusCode)
	}
}

func TestAdminOTPHTTPBoundaries(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	res, _ := c.request("POST", otpRoute+"register/begin", "{}", http.Header{"Content-Type": {"application/json"}})
	if res.StatusCode != 401 {
		t.Fatal("anonymous enrollment")
	}
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ = otpPost(c, "register/begin", struct{}{})
	if res.StatusCode != 403 {
		t.Fatal("no reauth enrollment")
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	res, _ = c.request("POST", otpRoute+"register/begin", "{}", http.Header{"Content-Type": {"application/json"}})
	if res.StatusCode != 403 {
		t.Fatal("missing csrf")
	}
	res, _ = otpPost(c, "policy", map[string]bool{"password_disabled": true})
	if res.StatusCode != 403 {
		t.Fatal("password-only reauth changed policy")
	}
}

func TestAdminOTPStateEncoding(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	accounts, err := repo.administrators()
	if err != nil {
		t.Fatal(err)
	}
	a := accounts[0]
	sealed, err := repo.sealOTP(a, []byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}
	v := adminSecurityState{Admin: a.ID, OTPSealed: sealed}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var decoded adminSecurityState
	decodeErr := strictjson.Decode(raw, &decoded)
	t.Logf("sealed length=%d decoded length=%d decode error=%v", len(sealed), len(decoded.OTPSealed), decodeErr)
	if err := validateAdminSecurity(a.ID.String(), nil, raw); err != nil {
		t.Fatal(err)
	}
}

// TestAdminOTPBrowser は既存Playwright環境を指定した時だけ、OTPと一時秘密の画面操作を実行する。
func TestAdminOTPBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("ブラウザ環境未指定")
	}
	for _, mount := range []string{"", "/admin"} {
		for _, script := range []string{"test-admin-otp-browser.mjs", "test-admin-recovery-browser.mjs"} {
			t.Run(mount+"/"+script, func(t *testing.T) {
				_, repo := adminFixture(t)
				defer repo.Close()
				server := httptest.NewUnstartedServer(nil)
				defer server.Close()
				origin := "http://localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
				repo.cfg.Admin.Origin = origin
				if mount != "" {
					repo.cfg.Admin.Transport = "public_path"
					repo.cfg.Admin.Origin = origin + mount
					repo.cfg.Public.BaseURL = origin
				}
				admin, err := repo.AdminHTTPServer()
				if err != nil {
					t.Fatal(err)
				}
				server.Config.Handler = admin.Handler
				server.Start()
				scriptPath, err := filepath.Abs("../../scripts/" + script)
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(t.Context(), node, scriptPath)
				cmd.Env = append(os.Environ(), "OIMO_PASSKEY_URL="+origin+mount, "OIMO_TEST_PASSWORD="+adminTestSecret)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("browser: %v\n%s", err, out)
				}
				t.Log(string(out))
			})
		}
	}
}
