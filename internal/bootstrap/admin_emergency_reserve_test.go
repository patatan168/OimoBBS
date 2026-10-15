// 管理HTTPの実割当・補充・再送と、容量競合・失敗・権限の境界を検証する。
package bootstrap

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
)

func TestEmergencyReserveOnlineHTTP(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, page := client.request("GET", "/maintenance", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "復旧用予約を導入（256MiB）") {
		t.Fatal(res.StatusCode, page)
	}
	fields := pageFields(page)
	formHeaders := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, body := client.request("POST", "/maintenance/emergency-reserve", fields.Encode(), formHeaders)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/maintenance" {
		t.Fatal(res.StatusCode, body)
	}
	status, err := inspectEmergencyReserve(cfg.DataDir)
	if err != nil || !status.Ready || status.AllocatedBytes < emergencyReserveBytes {
		t.Fatal(status, err)
	}
	res, page = client.request("GET", "/maintenance", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "確保済み") || strings.Contains(page, "action=\"/maintenance/emergency-reserve\"") {
		t.Fatal(res.StatusCode, page)
	}
	// 同じフォームの再送は既存領域を維持して成功する。
	res, body = client.request("POST", "/maintenance/emergency-reserve", fields.Encode(), formHeaders)
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode, body)
	}
	// 未完了の保存状態を作り、管理API経由で補充する。
	if err = os.Truncate(filepath.Join(cfg.DataDir, emergencyReserveName), 240<<20); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	repo.capacityClock = func() time.Time { return now }
	res, body = client.request("GET", "/api/v1/maintenance", "", nil)
	token := res.Header.Get("X-CSRF-Token")
	if token == "" || !strings.Contains(body, `"write_ready":false`) {
		t.Fatal(body)
	}
	headers := http.Header{"X-CSRF-Token": {token}}
	res, body = client.request("POST", emergencyReserveRoute, "", headers)
	if res.StatusCode != 200 || !strings.Contains(body, `"ready":true`) {
		t.Fatal(res.StatusCode, body)
	}
	if status := repo.PostingCapacity(); status.WriteReady || !status.Recovering {
		t.Fatal(status)
	}
	for i := 0; i < 30; i++ {
		now = now.Add(time.Second)
		repo.PostingCapacity()
	}
	if status := repo.PostingCapacity(); !status.WriteReady {
		t.Fatal(status)
	}
	client.server.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if status := repo.PostingCapacity(); !status.WriteReady || !status.EmergencyReserve.Ready {
		t.Fatal(status)
	}
}

func TestEmergencyReserveOnlineRejectsUnsafeRequests(t *testing.T) {
	cfg, repo := adminFixture(t)
	limited, err := repo.CreateAdministrator("limited", "担当者", adminTestSecret, AdministratorAccess{Role: "moderator", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := client.request("GET", "/api/v1/maintenance", "", nil)
	token := res.Header.Get("X-CSRF-Token")
	for _, step := range []struct {
		method, body, token, origin string
		status                      int
	}{
		{"GET", "", token, client.origin, 405},
		{"POST", "", "", client.origin, 403},
		{"POST", "", "invalid", client.origin, 403},
		{"POST", `{"remaining_mib":0}`, token, client.origin, 400},
		{"POST", "", token, "http://outside.invalid", 403},
	} {
		res, body := client.request(step.method, emergencyReserveRoute, step.body, http.Header{"X-CSRF-Token": {step.token}, "Origin": {step.origin}})
		if res.StatusCode != step.status {
			t.Fatal(step, res.StatusCode, body)
		}
	}
	if _, err := os.Lstat(filepath.Join(cfg.DataDir, emergencyReserveName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	cookie, session, err := repo.adminAuth.Create(limited.ID, limited.Generation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: cookie}
	res, body := client.request("POST", emergencyReserveRoute, "", http.Header{"X-CSRF-Token": {session.CSRF(emergencyReserveRoute)}})
	if res.StatusCode != 403 {
		t.Fatal(res.StatusCode, body)
	}
	if _, err = repo.prepareEmergencyReserve(session, nil); err == nil {
		t.Fatal("viewer allowed")
	}
}

func TestEmergencyReserveOnlineCapacityAndFailure(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	session, err := repo.adminAuth.Lookup(client.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	floor := uint64(1 << 30)
	repo.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 8 << 30, Available: floor + uint64(emergencyReserveBytes)}, nil
	}
	for _, held := range []*uint64{&repo.postReserved, &repo.packReserved, &repo.backupReserved} {
		*held = 1
		_, err = repo.prepareEmergencyReserve(session, func(*os.File) error { t.Fatal("allocation despite reservations"); return nil })
		var failure *adminFailure
		if !errors.As(err, &failure) || failure.code != "RESERVE_CAPACITY_UNAVAILABLE" {
			t.Fatal(err)
		}
		*held = 0
	}
	path := filepath.Join(cfg.DataDir, emergencyReserveName)
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	_, err = repo.prepareEmergencyReserve(session, func(f *os.File) error {
		if err := f.Truncate(64 << 20); err != nil {
			return err
		}
		return syscall.ENOSPC
	})
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatal(err)
	}
	if status := repo.PostingCapacity(); status.WriteReady || !status.EmergencyReserve.Enabled || status.EmergencyReserve.Ready {
		t.Fatal(status)
	}
	_, err = repo.prepareEmergencyReserve(session, func(f *os.File) error { return f.Truncate(emergencyReserveBytes) })
	if err == nil {
		t.Fatal("sparse allocation accepted")
	}
	// 再実行で実割当を完了できる。
	_, err = repo.prepareEmergencyReserve(session, func(f *os.File) error { return syscall.Fallocate(int(f.Fd()), 0, 0, emergencyReserveBytes) })
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.prepareEmergencyReserve(session, func(*os.File) error { t.Fatal("ready reserve allocated twice"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	repo.adminAuth.Delete(client.cookies["oimo_admin"].Value)
	_, err = repo.prepareEmergencyReserve(session, nil)
	if !errors.Is(err, adminauth.ErrSession) {
		t.Fatal(err)
	}
}
