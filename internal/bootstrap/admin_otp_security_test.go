// OTP登録の期限・容量・暗号状態の単調性と、保存失敗時の認証拒否を検証する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

func TestAdminOTPEnrollmentMemoryBoundaries(t *testing.T) {
	var pending otpEnrollments
	now := time.Unix(1800000000, 0)
	flow := &otpEnrollment{Binding: "browser", Secret: make(sealedOTP, 48)}
	flow.Secret[0] = 7
	token, err := pending.put(flow, now)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := pending.peek(token, "other", now); ok {
		t.Fatal("QR leaked to another session")
	}
	snapshot, ok := pending.peek(token, "browser", now)
	if !ok || snapshot.Secret[0] != 7 {
		t.Fatal("QR snapshot unavailable")
	}
	clear(snapshot.Secret)
	if flow.Secret[0] != 7 {
		t.Fatal("QR snapshot aliased pending secret")
	}
	if _, ok := pending.take(token, "other", now); ok {
		t.Fatal("wrong browser accepted")
	}
	if !bytes.Equal(flow.Secret, make([]byte, 48)) {
		t.Fatal("rejected enrollment retained ciphertext")
	}
	if _, ok := pending.take(token, "browser", now); ok {
		t.Fatal("setup replay")
	}
	for range 128 {
		if _, err := pending.put(&otpEnrollment{Binding: "browser", Secret: make(sealedOTP, 48)}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pending.put(&otpEnrollment{}, now); err == nil {
		t.Fatal("unbounded enrollments")
	}
	token, err = pending.put(&otpEnrollment{Binding: "browser", Secret: make(sealedOTP, 48)}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal("expired enrollment not pruned", err)
	}
	if _, ok := pending.peek(token, "browser", now.Add(4*time.Minute)); ok {
		t.Fatal("expired QR available")
	}
	if _, ok := pending.take(token, "browser", now.Add(4*time.Minute)); ok {
		t.Fatal("expired enrollment accepted")
	}
}

func TestAdminOTPPersistentWatermarkValidation(t *testing.T) {
	a := domain.NewID()
	prior := adminSecurityState{Admin: a, OTPSealed: make(sealedOTP, 48), NextStep: 42}
	raw, _ := json.Marshal(prior)
	next := prior
	next.NextStep = 41
	encoded, _ := json.Marshal(next)
	if validateAdminSecurity(a.String(), raw, encoded) == nil {
		t.Fatal("OTP watermark rollback accepted")
	}
	next.NextStep = 43
	encoded, _ = json.Marshal(next)
	if err := validateAdminSecurity(a.String(), raw, encoded); err != nil {
		t.Fatal(err)
	}
	for _, ciphertext := range []sealedOTP{nil, make(sealedOTP, 1), make(sealedOTP, 47), make(sealedOTP, 49)} {
		next.OTPSealed = ciphertext
		encoded, _ = json.Marshal(next)
		if validateAdminSecurity(a.String(), raw, encoded) == nil {
			t.Fatal("invalid ciphertext accepted")
		}
	}
}

func TestAdminOTPSaveFailureDoesNotAuthenticate(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	secret := enrollTestOTP(t, c)
	if err := repo.site.Close(); err != nil {
		t.Fatal(err)
	}
	res, _ := otpPost(c, "login", map[string]string{"login": "owner", "password": adminTestSecret, "code": otpTestCode(secret, 0)})
	if res.StatusCode != 503 {
		t.Fatal("save failure allowed authentication", res.StatusCode)
	}
	if cookie := c.cookies["oimo_admin"]; cookie != nil {
		t.Fatal("save failure issued cookie")
	}
	repo.mu.Lock()
	stopped := repo.stopped
	repo.mu.Unlock()
	if !stopped {
		t.Fatal("uncertain save did not stop repository")
	}
}

func TestAdminPasswordTemporaryExpiryAndReissue(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.cfg.Admin.Origin = "http://localhost:9081"
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	target := createRecoveryAccount(t, c, "moderator")
	s, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	first, err := repo.resetTemporaryPassword(s, target.ID, target.ETag(), domain.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	accounts, _ := repo.administrators()
	var a administrator
	for _, v := range accounts {
		if v.ID == target.ID {
			a = v
		}
	}
	security, _, err := repo.adminSecurityLocked(a)
	if err == nil {
		security.TemporaryExpires = domain.Time(time.Now().Add(-time.Second).UnixNano())
		err = repo.saveAdminSecurityLocked(a, security, "administrator_temporary_expiry_test", false)
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	person := newAdminClient(t, repo)
	defer person.server.Close()
	if res, _ := loginAdminAs(person, a.Login, first); res.StatusCode != 401 {
		t.Fatal("expired temporary password accepted", res.StatusCode)
	}
	detail, _ := c.request("GET", "/api/v1/administrators/"+target.ID.String(), "", nil)
	second, err := repo.resetTemporaryPassword(s, target.ID, detail.Header.Get("ETag"), domain.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("temporary password reused")
	}
	if res, _ := loginAdminAs(person, a.Login, first); res.StatusCode != 401 {
		t.Fatal("reissued old password accepted", res.StatusCode)
	}
	if res, _ := loginAdminAs(person, a.Login, second); res.StatusCode != 303 {
		t.Fatal("reissued password rejected", res.StatusCode)
	}
	// 制限セッションにはOTP経由の登録や方針変更も許可しない。
	res, _ := person.request("POST", otpRoute+"policy", `{"password_disabled":false}`, http.Header{"Content-Type": {"application/json"}})
	if res.StatusCode != 403 {
		t.Fatal("restricted session changed policy")
	}
}
