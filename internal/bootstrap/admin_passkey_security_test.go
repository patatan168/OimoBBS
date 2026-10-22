// パスキーの未認証応答、試行枠の分離、削除時の全セッション失効を実HTTPで検証する。
package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func passkeySecurityFixture(t *testing.T) (*Repository, *adminClient, administrator) {
	t.Helper()
	_, repo := adminFixture(t)
	t.Cleanup(func() { repo.Close() })
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	t.Cleanup(c.server.Close)
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("setup authentication")
	}
	s, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	a, err := repo.currentAdminSession(s)
	if err != nil {
		t.Fatal(err)
	}
	keys := adminPasskeySet{Admin: a.ID, RPID: "localhost", Keys: []adminPasskey{{Name: "phone", Created: domain.Time(time.Now().UnixNano()), Credential: webauthn.Credential{ID: []byte("security-test-credential"), PublicKey: []byte("state-fixture-only")}}}}
	h := adminHandler{repo: repo}
	if err := h.savePasskeysLocked(a, 0, keys, "administrator_passkey_register"); err != nil {
		t.Fatal(err)
	}
	return repo, c, a
}

// passkeyLoginBegin は未ログインのブラウザとして新しいnonceとCSRFで開始する。
func passkeyLoginBegin(t *testing.T, c *adminClient, login string) (*http.Response, string) {
	t.Helper()
	_, page := c.request("GET", "/login", "", nil)
	body, _ := json.Marshal(passkeyInput{Login: login})
	return c.request("POST", passkeyRoute+"login/begin", string(body), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {pageFields(page).Get("csrf")}})
}

func TestAdminPasskeyLoginDoesNotRevealAccount(t *testing.T) {
	repo, _, a := passkeySecurityFixture(t)
	var expected map[string]any
	for _, login := range []string{"", "owner", "unknown-account"} {
		c := newAdminClient(t, repo)
		res, body := passkeyLoginBegin(t, c, login)
		if res.StatusCode != 200 {
			c.server.Close()
			t.Fatalf("account-specific status for %s: %d %s", login, res.StatusCode, body)
		}
		var options map[string]any
		if err := json.Unmarshal([]byte(body), &options); err != nil {
			t.Fatal(err)
		}
		key := options["publicKey"].(map[string]any)
		if ids, ok := key["allowCredentials"]; ok && ids != nil {
			t.Fatal("credential IDs exposed before authentication", ids)
		}
		if key["challenge"] == "" {
			t.Fatal("missing challenge")
		}
		delete(key, "challenge")
		if expected != nil && !reflect.DeepEqual(expected, options) {
			t.Fatal("account-dependent options", options, expected)
		}
		expected = options
		rejected, failure := c.request("POST", passkeyRoute+"login/finish", `{}`, http.Header{"Content-Type": {"application/json"}})
		if rejected.StatusCode != 401 {
			t.Fatal("invalid assertion accepted", rejected.StatusCode, failure)
		}
		c.server.Close()
	}
	// 鍵がない既存アカウントも同じ開始応答を返す。
	repo.mu.Lock()
	h := adminHandler{repo: repo}
	_, revision, err := repo.passkeysLocked(a, "localhost")
	if err == nil {
		err = h.savePasskeysLocked(a, revision, adminPasskeySet{Admin: a.ID, RPID: "localhost", Keys: []adminPasskey{}}, "administrator_passkey_remove")
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	res, body := passkeyLoginBegin(t, c, "")
	if res.StatusCode != 200 {
		t.Fatal("keyless account disclosed", res.StatusCode, body)
	}
}

func TestAdminPasskeyBeginDoesNotConsumePasswordAttempts(t *testing.T) {
	repo, _, _ := passkeySecurityFixture(t)
	attacker := newAdminClient(t, repo)
	defer attacker.server.Close()
	for i := 0; i < 5; i++ {
		res, body := passkeyLoginBegin(t, attacker, "owner")
		if res.StatusCode != 200 {
			t.Fatalf("begin %d: %d %s", i, res.StatusCode, body)
		}
	}
	limited, _ := passkeyLoginBegin(t, attacker, "another-name")
	if limited.StatusCode != 429 {
		t.Fatal("passkey source limit missing", limited.StatusCode)
	}
	legitimate := newAdminClient(t, repo)
	defer legitimate.server.Close()
	if legitimate.login(adminTestSecret) != 303 || legitimate.reauth(adminTestSecret) != 200 {
		t.Fatal("passkey begin exhausted password login or reauthentication")
	}
}

func TestAdminPasskeyRemovalRevokesSessionsAndPendingLogin(t *testing.T) {
	repo, c, a := passkeySecurityFixture(t)
	other := newAdminClient(t, repo)
	defer other.server.Close()
	if other.login(adminTestSecret) != 303 {
		t.Fatal("second login")
	}
	queued, err := repo.adminAuth.Lookup(other.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	invalid, _ := c.request("POST", passkeyRoute+"remove/finish", `{"id":"dW5rbm93bg"}`, http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {s.CSRF(passkeyRoute)}})
	if invalid.StatusCode != 404 {
		t.Fatal("unknown key removal", invalid.StatusCode)
	}
	alive, _ := other.request("GET", "/api/v1/site", "", nil)
	if alive.StatusCode != 200 {
		t.Fatal("failed removal revoked sessions", alive.StatusCode)
	}
	id := base64.RawURLEncoding.EncodeToString([]byte("security-test-credential"))
	res, body := c.request("POST", passkeyRoute+"remove/finish", `{"id":"`+id+`"}`, http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {s.CSRF(passkeyRoute)}})
	if res.StatusCode != 200 {
		t.Fatal("removal", res.StatusCode, body)
	}
	for _, client := range []*adminClient{c, other} {
		res, _ := client.request("GET", "/api/v1/site", "", nil)
		if res.StatusCode != 401 {
			t.Fatal("session survived key removal", res.StatusCode)
		}
	}
	repo.mu.Lock()
	_, sessionErr := repo.currentAdminSession(queued)
	_, accountErr := repo.currentAdminAccount(queued)
	keys, _, keyErr := repo.passkeysLocked(a, "localhost")
	repo.mu.Unlock()
	if sessionErr == nil || accountErr == nil {
		t.Fatal("queued session or old login generation survived")
	}
	if keyErr != nil || len(keys.Keys) != 0 {
		t.Fatal("key deletion", keyErr)
	}
	if c.login(adminTestSecret) != 303 {
		t.Fatal("password recovery login failed")
	}
	c.server.Close()
	other.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPostingRepository(repo.cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.mu.Lock()
	defer reopened.mu.Unlock()
	if _, err := reopened.currentAdminAccount(queued); err == nil {
		t.Fatal("old generation survived restart")
	}
	if _, err := reopened.currentAdminAccount(adminauth.Session{Admin: a.ID, Generation: a.Generation + 1}); err != nil {
		t.Fatal("new generation was not saved with deletion", err)
	}
}

func TestAdminPasskeyLoginRequiresNonce(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	headers := http.Header{"Content-Type": {"application/json"}}
	const body = `{}`
	missing, _ := c.request("POST", passkeyRoute+"login/begin", body, headers)
	if missing.StatusCode != 403 {
		t.Fatal("missing nonce accepted", missing.StatusCode)
	}
	_, page := c.request("GET", "/login", "", nil)
	headers.Set("X-CSRF-Token", "forged")
	forged, _ := c.request("POST", passkeyRoute+"login/begin", body, headers)
	if forged.StatusCode != 403 {
		t.Fatal("forged CSRF accepted", forged.StatusCode)
	}
	headers.Set("X-CSRF-Token", pageFields(page).Get("csrf"))
	valid, _ := c.request("POST", passkeyRoute+"login/begin", body, headers)
	if valid.StatusCode != 200 {
		t.Fatal("valid nonce rejected", valid.StatusCode)
	}
	replay, _ := c.request("POST", passkeyRoute+"login/begin", body, headers)
	if replay.StatusCode != 403 {
		t.Fatal("nonce replay accepted", replay.StatusCode)
	}
}

// TestAdminPasskeyLoginCredentialOwnership はID入力に頼らず、鍵の所属と管理者の有効状態を照合する。
// ここでは鍵の解決を確認し、署名・本人確認フラグの検証はブラウザー試験で行う。
func TestAdminPasskeyLoginCredentialOwnership(t *testing.T) {
	repo, _, account := passkeySecurityFixture(t)
	access := AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true}
	other, err := repo.CreateAdministrator("other-owner", "別の管理者", adminTestSecret, access)
	if err != nil {
		t.Fatal(err)
	}
	h := adminHandler{repo: repo}
	reopen := func() {
		t.Helper()
		cfg := repo.cfg
		if err := repo.Close(); err != nil {
			t.Fatal(err)
		}
		var err error
		repo, err = OpenPostingRepository(cfg, postcapture.Validate)
		if err != nil {
			t.Fatal(err)
		}
		opened := repo
		t.Cleanup(func() { opened.Close() })
		h.repo = repo
	}
	reopen()
	credential := []byte("security-test-credential")
	check := func(handle, key []byte, allowed bool) {
		t.Helper()
		repo.mu.Lock()
		var verified verifiedPasskey
		err := h.loadPasskeyLogin(&verified, key, handle, "localhost")
		repo.mu.Unlock()
		if (err == nil) != allowed || allowed && verified.Account.ID != account.ID {
			t.Fatalf("credential owner resolution: allowed=%v, err=%v", allowed, err)
		}
	}
	check(account.ID[:], credential, true)
	check(other.ID[:], credential, false)
	check(account.ID[:], []byte("unknown-key"), false)
	check(nil, credential, false)
	access.Enabled = false
	if _, err := repo.SetAdministratorAccess(account.Login, access); err != nil {
		t.Fatal(err)
	}
	reopen()
	check(account.ID[:], credential, false)
}

// TestAdminLoginFaviconKeepsForm は背景のアイコン取得がパスワード用フォームを失効させないことを確認する。
func TestAdminLoginFaviconKeepsForm(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	_, page := client.request("GET", "/login", "", nil)
	csrf := pageFields(page).Get("csrf")
	for _, method := range []string{"GET", "HEAD"} {
		res, _ := client.request(method, "/favicon.ico", "", nil)
		if res.StatusCode != 404 || len(res.Cookies()) != 0 {
			t.Fatal("favicon replaced login form", method, res.StatusCode)
		}
	}
	fields := url.Values{"login": {"owner"}, "password": {adminTestSecret}, "csrf": {csrf}}
	res, _ := client.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("password login after favicon request", res.StatusCode)
	}
}
