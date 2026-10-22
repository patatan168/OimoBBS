// 容量予約の境界、解放、圧縮延期中の回収と巡回予算を検証する。
package bootstrap

import (
	"context"
	"errors"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/platform"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPackCapacityReservations(t *testing.T) {
	floor := uint64(1 << 30)
	for _, total := range []uint64{2 << 30, 100 << 30} {
		minimum := max(floor, total/10)
		for _, reserved := range []uint64{0, packReservationBytes} {
			want := minimum + reserved + packReservationBytes
			if packCapacity(platform.DiskSpace{Total: total, Available: want - 1}, reserved) {
				t.Fatal("below threshold")
			}
			if !packCapacity(platform.DiskSpace{Total: total, Available: want}, reserved) {
				t.Fatal("exact threshold")
			}
		}
	}
	r := &Repository{}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: floor + packReservationBytes}, nil
	}
	release, e := r.reservePack()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.reservePack(); !errors.Is(e, app.ErrPackCapacity) {
		t.Fatal(e)
	}
	if s := r.MaintenanceStatus(); s.ReservedBytes != packReservationBytes || !s.CapacityKnown {
		t.Fatal(s)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(release)
	}
	wg.Wait()
	if s := r.MaintenanceStatus(); s.ReservedBytes != 0 {
		t.Fatal("double release", s)
	}
	release, e = r.reservePack()
	if e != nil {
		t.Fatal(e)
	}
	release()
	r.packSpace = func(string) (platform.DiskSpace, error) { return platform.DiskSpace{}, errors.New("private path") }
	if _, e = r.reservePack(); e == nil || e.Error() == "private path" {
		t.Fatal(e)
	}
}

func TestPackCapacityDefersAndReclaims(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "space", "容量試験")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	created, e := sendForm(server, url.Values{"bbs": {"space"}, "subject": {"容量試験"}, "MESSAGE": {"本文"}, "oimo_request_id": {"capacity-create-0001"}})
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	if _, e = r.EnablePostingPacks(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = r.CompactThread(ctx, info.ID, created.Key, 0, true); e != nil {
		t.Fatal(e)
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 1 << 30}, nil
	}
	if _, e = r.CompactThread(ctx, info.ID, created.Key, 1, true); !errors.Is(e, app.ErrPackCapacity) {
		t.Fatal(e)
	}
	report, e := r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil || len(report.Entries) != 1 {
		t.Fatal(report, e)
	}
	entry := report.Entries[0]
	if entry.Deferred != "capacity" || entry.Pack.Applied || entry.Reclaim.Files != 1 || !entry.Reclaim.Applied {
		t.Fatal(entry)
	}
	if s := r.MaintenanceStatus(); s.Failed || s.Deferred != 1 || s.ReservedBytes != 0 {
		t.Fatal(s)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, body := client.request("GET", "/maintenance", "", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "1024 MiB") || !strings.Contains(body, "容量不足で延期した圧縮</dt><dd>1") || !strings.Contains(body, "現在の整理用予約</dt><dd>0 MiB") {
		t.Fatal(response.StatusCode, body)
	}
	// 延期しても公開本文と投稿機能は停止しない。
	snapshot, e := r.Thread(ctx, info.ID, created.Key)
	if e != nil || snapshot == nil || snapshot.PostCount != 1 {
		t.Fatal(snapshot, e)
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 2 << 30}, nil
	}
	report, e = r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil || !report.Entries[0].Pack.Applied || report.Entries[0].Deferred != "" {
		t.Fatal(report, e)
	}
	if s := r.MaintenanceStatus(); s.ReservedBytes != 0 || s.Deferred != 0 {
		t.Fatal(s)
	}
	// 時間切れ直前にqueueへ入った要求も、保存開始前に延期する。
	instant := time.Now()
	count := 0
	r.maintenanceClock = func() time.Time {
		count++
		if count >= 4 {
			return instant.Add(30 * time.Second)
		}
		return instant
	}
	report, e = r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil || report.StopReason != "time_budget" || len(report.Entries) != 0 || report.DurationMillis != 30000 {
		t.Fatal(report, e, count)
	}
	r.maintenanceClock = nil
	report, e = r.MaintainPostingPacks(ctx, 10, report.Next, true)
	if e != nil || len(report.Entries) != 1 || report.Entries[0].Pack.Applied {
		t.Fatal(report, e)
	}
}
