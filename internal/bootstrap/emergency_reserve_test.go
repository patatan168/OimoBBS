// 予約の実割当、停止中排他、中断状態、解放後の受付停止を検証する。
package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"oimobbs/internal/app"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
)

func TestEmergencyReserveLifecycle(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "reserve"); e != nil {
		t.Fatal(e)
	}
	s, e := ManageEmergencyReserve(cfg, "prepare", 0, false)
	if e != nil || s.Enabled {
		t.Fatal(s, e)
	}
	s, e = ManageEmergencyReserve(cfg, "prepare", 0, true)
	if e != nil || !s.Ready || s.AllocatedBytes < 256<<20 {
		t.Fatal(s, e)
	}
	if _, e = Check(cfg); e != nil {
		t.Fatal(e)
	}
	r, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ManageEmergencyReserve(cfg, "release", 240<<20, true); e == nil {
		t.Fatal("live writer was not excluded")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = ManageEmergencyReserve(cfg, "release", 240<<20, true)
	if e != nil || s.Ready || s.Bytes != 240<<20 {
		t.Fatal(s, e)
	}
	// 同じ指定を再実行しても追加の解放はしない。
	s, e = ManageEmergencyReserve(cfg, "release", 240<<20, true)
	if e != nil || s.Bytes != 240<<20 {
		t.Fatal(s, e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 8 << 30, Available: 7 << 30}, nil
	}
	if s := r.PostingCapacity(); s.WriteReady || !s.EmergencyReserve.Enabled || s.EmergencyReserve.Ready {
		t.Fatal(s)
	}
	if _, e = r.reservePosting(); !errors.Is(e, ErrPostingCapacity) {
		t.Fatal(e)
	}
	if _, e = r.reservePack(); !errors.Is(e, app.ErrPackCapacity) {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = ManageEmergencyReserve(cfg, "release", 0, true)
	if e != nil || s.Bytes != 0 || !s.Enabled {
		t.Fatal(s, e)
	}
	s, e = ManageEmergencyReserve(cfg, "prepare", 0, true)
	if e != nil || !s.Ready {
		t.Fatal(s, e)
	}
	// 補充後の再起動でのみ再開する（操作は停止中限定）。
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 8 << 30, Available: 7 << 30}, nil
	}
	release, e := r.reservePosting()
	if e != nil {
		t.Fatal(e)
	}
	release()
}

func TestEmergencyReserveInterruptedAndUnsafeFiles(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "reserve"); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(cfg.DataDir, emergencyReserveName)
	if e := os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	// 確保開始直後の空fileと、truncateのみの疎fileはともに未確保。
	for _, size := range []int64{0, emergencyReserveBytes} {
		if e := os.Truncate(path, size); e != nil {
			t.Fatal(e)
		}
		s, e := ManageEmergencyReserve(cfg, "status", 0, false)
		if e != nil || !s.Enabled || s.Ready {
			t.Fatal(s, e)
		}
	}
	if e := os.Truncate(path, emergencyReserveBytes+1); e != nil {
		t.Fatal(e)
	}
	if _, e := Check(cfg); e == nil {
		t.Fatal("oversized reserve accepted")
	}
	if e := os.Truncate(path, 0); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ManageEmergencyReserve(cfg, "status", 0, false); e == nil {
		t.Fatal("public file accepted")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(path, filepath.Join(t.TempDir(), "alias")); e != nil {
		t.Fatal(e)
	}
	if _, e := ManageEmergencyReserve(cfg, "release", 0, true); e == nil {
		t.Fatal("hardlink accepted")
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(cfg.DataDir, "instance.json"), path); e != nil {
		t.Fatal(e)
	}
	if _, e := ManageEmergencyReserve(cfg, "prepare", 0, true); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestEmergencyReserveAllocationFailure(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "reserve"); e != nil {
		t.Fatal(e)
	}
	_, e := manageEmergencyReserve(cfg, "prepare", 0, true, func(f *os.File) error {
		if e := f.Truncate(64 << 20); e != nil {
			return e
		}
		return syscall.ENOSPC
	})
	if !errors.Is(e, syscall.ENOSPC) {
		t.Fatal(e)
	}
	r, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if s := r.PostingCapacity(); s.WriteReady || !s.EmergencyReserve.Enabled {
		t.Fatal(s)
	}
}

func TestEmergencyReserveAdmin(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	// 確保処理が中断した永続状態を用意する。実運用の操作は停止中限定。
	if e := os.WriteFile(filepath.Join(cfg.DataDir, emergencyReserveName), nil, 0600); e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, body := client.request("GET", "/maintenance", "", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "補充が必要（投稿・圧縮停止）") {
		t.Fatal(response.StatusCode, body)
	}
	_, body = client.request("GET", "/api/v1/maintenance", "", nil)
	if !strings.Contains(body, `"emergency_reserve":{"enabled":true,"ready":false`) || !strings.Contains(body, `"write_ready":false`) {
		t.Fatal(body)
	}
}

// TestEmergencyReserveRecoveryBoundary は通常起動できない状態でも解放だけを許可し、補充は拒否する。
func TestEmergencyReserveRecoveryBoundary(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "reserve"); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(cfg.DataDir, emergencyReserveName)
	if e := os.WriteFile(path, []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(cfg.DataDir, "recovery-unknown"), []byte("pending"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Check(cfg); e == nil {
		t.Fatal("invalid root accepted")
	}
	s, e := ManageEmergencyReserve(cfg, "release", 0, true)
	if e != nil || s.Bytes != 0 || !s.Enabled {
		t.Fatal(s, e)
	}
	// より大きな残量を指定しても、解放コマンドで再割当はしない。
	s, e = ManageEmergencyReserve(cfg, "release", 240<<20, true)
	if e != nil || s.Bytes != 0 {
		t.Fatal(s, e)
	}
	if _, e = ManageEmergencyReserve(cfg, "prepare", 0, true); e == nil {
		t.Fatal("refilled unverified root")
	}
	s, e = ManageEmergencyReserve(cfg, "status", 0, false)
	if e != nil || s.Bytes != 0 || s.Ready {
		t.Fatal(s, e)
	}
}
