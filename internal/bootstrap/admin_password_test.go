// Webの下位管理者復旧・一時秘密の変更強制・サイト管理者のCLI限定を実HTTPで確認する。
package bootstrap

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func loginAdminAs(c *adminClient, login, secret string) (*http.Response, string) {
	c.t.Helper()
	_, page := c.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", login)
	fields.Set("password", secret)
	return c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
}

func createRecoveryAccount(t *testing.T, c *adminClient, role string) AdminAccount {
	t.Helper()
	list, _ := c.request("GET", "/api/v1/administrators", "", nil)
	in := accountInput{Login: "recover.user", Display: "復旧対象", Password: "initial-recovery-user-password", Access: AdministratorAccess{Role: role, Boards: []domain.ID{}, Permissions: []string{}, Enabled: true}}
	res, a, _ := c.accountChange("POST", "/api/v1/administrators", in, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal("create account", res.StatusCode)
	}
	return a
}

func TestAdminTemporaryPasswordRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	cfg = repo.cfg
	owner := newAdminClient(t, repo)
	defer owner.server.Close()
	if owner.login(adminTestSecret) != 303 || owner.reauth(adminTestSecret) != 200 {
		t.Fatal("owner auth")
	}
	target := createRecoveryAccount(t, owner, "moderator")
	person := newAdminClient(t, repo)
	person.server.Client().Transport = &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).DialContext}
	defer person.server.Client().CloseIdleConnections()
	defer person.server.Close()
	if res, _ := loginAdminAs(person, "recover.user", "initial-recovery-user-password"); res.StatusCode != 303 {
		t.Fatal("user login")
	}
	// 旧OTPとパスワード禁止があっても、明示した管理者復旧だけが両方を解除できる。
	repo.mu.Lock()
	accounts, _ := repo.administrators()
	var a administrator
	for _, v := range accounts {
		if v.ID == target.ID {
			a = v
		}
	}
	secret := []byte("12345678901234567890")
	h := adminHandler{repo: repo}
	keys := adminPasskeySet{Admin: a.ID, RPID: "localhost", Keys: []adminPasskey{{Name: "old phone", Created: domain.Time(time.Now().UnixNano()), Credential: webauthn.Credential{ID: []byte("old-key"), PublicKey: []byte("state-fixture-only")}}}}
	if err := h.savePasskeysLocked(a, 0, keys, "administrator_passkey_register"); err != nil {
		repo.mu.Unlock()
		t.Fatal(err)
	}
	sealed, err := repo.sealOTP(a, secret)
	if err == nil {
		err = repo.saveAdminSecurityLocked(a, adminSecurityState{Admin: a.ID, OTPSealed: sealed, PasswordDisabled: true}, "administrator_otp_test", false)
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/administrators/" + a.ID.String()
	detail, _ := owner.request("GET", path, "", nil)
	session, err := repo.adminAuth.Lookup(owner.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resetRoute := path + "/password-reset"
	res, body := owner.request("POST", resetRoute, "{}", http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {session.CSRF(resetRoute)}, "If-Match": {detail.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal("reset", res.StatusCode, body)
	}
	var issued struct {
		Temporary string `json:"temporary_password"`
	}
	if json.Unmarshal([]byte(body), &issued) != nil || len(issued.Temporary) < 32 {
		t.Fatal("temporary secret missing")
	}
	if res, _ := person.request("GET", "/api/v1/reauth", "", nil); res.StatusCode != 401 {
		t.Fatal("old session survived")
	}
	if _, err := repo.ConfigureAdministrator("recover.user", "復旧対象", "command-must-not-reset-lower-admin", true); err == nil {
		t.Fatal("lower admin reset via CLI")
	}
	res, _ = loginAdminAs(person, "recover.user", issued.Temporary)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/password" {
		t.Fatal("temporary login", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := person.request("GET", "/api/v1/reauth", "", nil); res.StatusCode != 403 {
		t.Fatal("temporary session used admin API")
	}
	if res, _ := person.request("GET", "/passkeys", "", nil); res.StatusCode != 303 || res.Header.Get("Location") != "/password" {
		t.Fatal("temporary session accessed registration")
	}
	res, _ = person.request("GET", "/api/v1/password", "", nil)
	csrf := res.Header.Get("X-CSRF-Token")
	data, _ := json.Marshal(map[string]string{"current_password": issued.Temporary, "new_password": "user-chosen-new-private-password"})
	res, body = person.request("POST", "/api/v1/password", string(data), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {csrf}})
	if res.StatusCode != 200 {
		t.Fatal("password change", res.StatusCode, body)
	}
	if res, _ := loginAdminAs(person, "recover.user", issued.Temporary); res.StatusCode != 401 {
		t.Fatal("temporary password survived change")
	}
	if res, _ := loginAdminAs(person, "recover.user", "user-chosen-new-private-password"); res.StatusCode != 303 {
		t.Fatal("new password login", res.StatusCode)
	}
	if res, _ := person.request("GET", "/api/v1/reauth", "", nil); res.StatusCode != 200 {
		t.Fatal("changed session remains restricted", res.StatusCode)
	}
	owner.server.Close()
	person.server.Close()
	repo.Close()
	reopened, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen", err)
	}
	defer reopened.Close()
	reopened.mu.Lock()
	defer reopened.mu.Unlock()
	security, _, err := reopened.adminSecurityLocked(a)
	keys, _, keyErr := reopened.passkeysLocked(a, "localhost")
	if keyErr != nil || len(keys.Keys) != 0 {
		t.Fatal("reset retained passkeys")
	}
	if err != nil || security.PasswordDisabled || security.PasswordChangeRequired || len(security.OTPSealed) > 0 {
		t.Fatal("reset state not durable")
	}
}

func TestAdminSiteAdministratorRecoveryIsOfflineOnly(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	target := createRecoveryAccount(t, c, "site_admin")
	detail, _ := c.request("GET", "/api/v1/administrators/"+target.ID.String(), "", nil)
	session, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	route := "/api/v1/administrators/" + target.ID.String() + "/password-reset"
	res, _ := c.request("POST", route, "{}", http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {session.CSRF(route)}, "If-Match": {detail.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 403 {
		t.Fatal("site administrator reset online", res.StatusCode)
	}
	in := accountInput{Login: target.Login, Display: target.Display, Access: target.Access}
	in.Access.Role = "moderator"
	res, _, _ = c.accountChange("PATCH", "/api/v1/administrators/"+target.ID.String(), in, detail.Header.Get("ETag"), detail.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 403 {
		t.Fatal("site administrator downgraded for recovery bypass", res.StatusCode)
	}
}
