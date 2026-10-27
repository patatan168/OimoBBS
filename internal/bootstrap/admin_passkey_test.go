// パスキーの期限・用途・ブラウザ束縛、保存復旧、既存HTTP境界と仮想認証器を検証する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestAdminPasskeyCeremonyBoundaries(t *testing.T) {
	now := time.Now()
	var p passkeyCeremonies
	for _, tc := range []struct {
		kind, binding string
		at            time.Time
		valid         bool
	}{
		{"login", "browser", now, true}, {"register", "browser", now, false}, {"login", "other", now, false}, {"login", "browser", now.Add(2 * time.Minute), false},
	} {
		token, err := p.put(passkeyCeremony{Kind: "login", Binding: "browser"}, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.take(token, tc.kind, tc.binding, tc.at); ok != tc.valid {
			t.Fatal("ceremony binding")
		}
		if _, ok := p.take(token, "login", "browser", now); ok {
			t.Fatal("ceremony replay")
		}
	}
	for range 1024 {
		if _, err := p.put(passkeyCeremony{}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.put(passkeyCeremony{}, now); err == nil {
		t.Fatal("unbounded ceremonies")
	}
	if _, err := p.put(passkeyCeremony{}, now.Add(2*time.Minute)); err != nil {
		t.Fatal("expired ceremonies not reclaimed")
	}
}

func TestAdminPasskeyHTTPBoundaries(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	for _, path := range []string{"/passkeys", passkeyRoute + "register/begin", passkeyRoute + "reauth/begin", passkeyRoute + "remove/finish"} {
		method := "POST"
		if path == "/passkeys" {
			method = "GET"
		}
		res, _ := c.request(method, path, `{}`, http.Header{"Content-Type": {"application/json"}})
		if res.StatusCode != 401 {
			t.Fatal("anonymous passkey access", path, res.StatusCode)
		}
	}
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := c.request("GET", "/passkeys", "", nil)
	if !strings.Contains(page, "自分のパスキー") {
		t.Fatal("passkey page")
	}
	if strings.Contains(page, "data-passkey-register") || !strings.Contains(page, "再認証して登録・削除へ進む") {
		t.Fatal("registration must guide a freshly logged-in administrator to reauthentication")
	}
	s, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {s.CSRF(passkeyRoute)}}
	for _, path := range []string{passkeyRoute + "register/begin", passkeyRoute + "remove/finish"} {
		res, _ := c.request("POST", path, `{"name":"phone"}`, headers)
		if res.StatusCode != 403 {
			t.Fatal("registration without reauthentication", res.StatusCode)
		}
	}
	res, _ := c.request("POST", passkeyRoute+"reauth/begin", `{}`, http.Header{"Content-Type": {"application/json"}})
	if res.StatusCode != 403 {
		t.Fatal("missing CSRF")
	}
	res, _ = c.request("POST", passkeyRoute+"reauth/begin", `{}`, http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {s.CSRF(passkeyRoute)}, "Origin": {"https://other.example"}})
	if res.StatusCode != 403 {
		t.Fatal("cross-origin passkey request")
	}
}

func TestAdminPasskeyPersistenceAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	c := newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	s, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	a, err := repo.currentAdminSession(s)
	if err != nil {
		t.Fatal(err)
	}
	keys := adminPasskeySet{Admin: a.ID, RPID: "localhost", Keys: []adminPasskey{{Name: "phone", Created: domain.Time(time.Now().UnixNano()), Credential: webauthn.Credential{ID: []byte("credential"), PublicKey: []byte("public-key")}}}}
	h := adminHandler{repo: repo}
	err = h.savePasskeysLocked(a, 0, keys, "administrator_passkey_register")
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// 鍵一覧の古い版による保存は拒否する。
	repo.mu.Lock()
	err = h.savePasskeysLocked(a, 0, keys, "administrator_passkey_register")
	repo.mu.Unlock()
	if err == nil {
		t.Fatal("stale passkey revision accepted")
	}
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	restored, _, err := repo.passkeysLocked(a, "localhost")
	repo.mu.Unlock()
	if err != nil || len(restored.Keys) != 1 || string(restored.Keys[0].Credential.ID) != "credential" {
		t.Fatal("passkeys lost after restart", err)
	}
	if _, err = repo.ConfigureAdministrator("owner", "所有者", adminTestSecret, true); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	repo.mu.Lock()
	restored, _, err = repo.passkeysLocked(a, "new.example")
	repo.mu.Unlock()
	if err != nil || len(restored.Keys) != 0 || restored.RPID != "new.example" {
		t.Fatal("offline recovery retained passkeys", err)
	}
}

// TestAdminPasskeyBrowser は環境指定時だけChromiumの仮想認証器で実際の画面操作と署名検証を行う。
func TestAdminPasskeyBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザ検証を有効化")
	}
	cases := []struct{ mount, negative, browser string }{{"", "", "chromium"}, {"/admin", "", "chromium"}, {"/admin", "signature", "chromium"}, {"/admin", "origin", "chromium"}, {"/admin", "challenge", "chromium"}, {"/admin", "verification", "chromium"}, {"/admin", "rp", "chromium"}, {"/admin", "login-verification", "chromium"}, {"/admin", "login-handle", "chromium"}, {"/admin", "login-key", "chromium"}}
	if os.Getenv("OIMO_FIREFOX") != "" {
		cases = append(cases, struct{ mount, negative, browser string }{"", "", "firefox"}, struct{ mount, negative, browser string }{"/admin", "", "firefox"})
	}
	for _, tc := range cases {
		mount := tc.mount
		t.Run(tc.browser+"/mount="+mount+"/reject="+tc.negative, func(t *testing.T) {
			cfg, repo := adminFixture(t)
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
			scriptName := "test-passkeys-browser.mjs"
			if tc.browser == "firefox" {
				scriptName = "test-passkeys-firefox.mjs"
			}
			script, err := filepath.Abs("../../scripts/" + scriptName)
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), node, script)
			command.Env = append(os.Environ(), "OIMO_PASSKEY_URL="+origin+mount, "OIMO_TEST_PASSWORD="+adminTestSecret, "OIMO_PASSKEY_NEGATIVE="+tc.negative)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("browser: %v\n%s", err, output)
			}
			t.Log(string(output))
			// 実際に登録・認証した鍵の状態を、サーバー停止・再オープン後にも検証する。
			server.Close()
			if err := repo.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal("browser state recovery", err)
			}
			defer reopened.Close()
			accounts, err := reopened.administrators()
			if err != nil {
				t.Fatal(err)
			}
			keys, _, err := reopened.passkeysLocked(accounts[0], "localhost")
			expected := 0
			if tc.negative != "" {
				expected = 1
			}
			if err != nil || len(keys.Keys) != expected {
				t.Fatal("browser keys not recovered", err)
			}
			if expected == 1 && (!keys.Keys[0].Credential.Flags.UserVerified || len(keys.Keys[0].Credential.PublicKey) == 0) {
				t.Fatal("verified public key lost")
			}
		})
	}
}

// TestAdminPasskeyInput は操作ごとの必須キー、未知キー、重複キーを検査する。
func TestAdminPasskeyInput(t *testing.T) {
	for _, tc := range []struct {
		kind, body string
		valid      bool
	}{
		{"login", `{}`, true}, {"login", `{"login":"owner"}`, true}, {"login", `{"login":"a","login":"b"}`, false}, {"register", `{"name":"phone"}`, true},
		{"reauth", `{}`, true}, {"remove", `{"id":"YQ"}`, true},
		{"register", `{}`, false}, {"login", `{"name":"owner"}`, false},
		{"register", `{"name":"a","name":"b"}`, false}, {"reauth", `{"id":"YQ"}`, false},
	} {
		_, err := decodePasskeyInput([]byte(tc.body), tc.kind)
		if (err == nil) != tc.valid {
			t.Fatal(tc.kind, tc.body, err)
		}
	}
}

// TestAdminPasskeyOnlinePasswordReset はサイト管理者のWebパスワード変更を拒否し、既存の鍵を保持する。
func TestAdminPasskeyOnlinePasswordReset(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	s, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	a, err := repo.currentAdminSession(s)
	if err != nil {
		repo.mu.Unlock()
		t.Fatal(err)
	}
	h := adminHandler{repo: repo}
	keys := adminPasskeySet{Admin: a.ID, RPID: "localhost", Keys: []adminPasskey{{Name: "phone", Created: domain.Time(time.Now().UnixNano()), Credential: webauthn.Credential{ID: []byte("credential"), PublicKey: []byte("public-key")}}}}
	err = h.savePasskeysLocked(a, 0, keys, "administrator_passkey_register")
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/administrators/" + a.ID.String()
	res, _ := c.request("GET", path, "", nil)
	input := accountInput{Login: a.Login, Display: a.Display, Password: "new-password-for-passkey-revocation", Access: AdministratorAccess{Role: a.Role, Boards: a.Boards, Permissions: a.Permissions, Enabled: true}}
	res, _, body := c.accountChange("PATCH", path, input, res.Header.Get("ETag"), res.Header.Get("X-CSRF-Token"), "passkey-password-change-0001")
	if res.StatusCode != 403 {
		t.Fatal("password change", res.StatusCode, body)
	}
	repo.mu.Lock()
	restored, _, err := repo.passkeysLocked(a, "localhost")
	repo.mu.Unlock()
	if err != nil || len(restored.Keys) != 1 {
		t.Fatal("rejected site administrator password reset changed passkeys", err)
	}
}
