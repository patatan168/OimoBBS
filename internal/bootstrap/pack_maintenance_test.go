// 自動整理の巡回・期限・再開・管理認証を実保存先と実HTTPで検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPackMaintenanceBatchAndRecovery(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	ctx := context.Background()
	type thread struct {
		owner domain.ID
		key   uint64
	}
	var threads []thread
	for i := 0; i < 3; i++ {
		boardKey := fmt.Sprintf("maint%d", i)
		board, e := r.CreateBoard(ctx, boardKey, "保守試験")
		if e != nil {
			t.Fatal(e)
		}
		server := formServer(t, r, siteID(r.site.State()), board.ID)
		created, e := sendForm(server, url.Values{"bbs": {boardKey}, "subject": {"保守試験"}, "MESSAGE": {"保存本文"}, "oimo_request_id": {fmt.Sprintf("maintenance-create-%04d", i)}})
		server.Close()
		if e != nil || !created.Accepted {
			t.Fatal(created, e)
		}
		threads = append(threads, thread{board.ID, created.Key})
		b := r.posting[board.ID]
		future := time.Now().Add(25 * time.Hour)
		if _, e = b.worker.Submit(ctx, func() (any, error) { b.clock = func() time.Time { return future }; return nil, nil }); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := r.MaintainPostingPacks(ctx, 1, "", true); e == nil {
		t.Fatal("version gate missing")
	}
	preview, e := r.MaintainPostingPacks(ctx, 1, "", false)
	if e != nil || len(preview.Entries) != 1 || preview.Next == "" || preview.Entries[0].Decision.Reason != "elapsed" || preview.Entries[0].Pack.Applied {
		t.Fatal(preview, e)
	}
	first := preview.Entries[0]
	path := filepath.Join(cfg.DataDir, "boards", first.Board.String(), "threads", fmt.Sprint(first.Thread))
	files, e := os.ReadDir(path)
	if e != nil || len(files) != 2 {
		t.Fatal("preview mutation", files, e)
	}
	if _, e = r.EnablePostingPacks(ctx); e != nil {
		t.Fatal(e)
	}
	// 混雑中の板は保守を入れず、他板の巡回を進める。
	busyStarted, busyRelease := make(chan struct{}), make(chan struct{})
	busyDone := make(chan error, 1)
	go func() {
		_, err := r.posting[first.Board].worker.Submit(ctx, func() (any, error) { close(busyStarted); <-busyRelease; return nil, nil })
		busyDone <- err
	}()
	<-busyStarted
	busyReport, busyErr := r.MaintainPostingPacks(ctx, 10, "", false)
	close(busyRelease)
	if e := <-busyDone; e != nil {
		t.Fatal(e)
	}
	if busyErr != nil || busyReport.BusyBoards != 1 || len(busyReport.Entries) != 2 || busyReport.StopReason != "queue_busy" || r.MaintenanceStatus().Failed {
		t.Fatal(busyReport, busyErr)
	}
	// 一板の保守が保存処理待ちでも、別板の公開読取りを全体lockで止めない。
	blocked := r.posting[first.Board]
	entered, release := make(chan struct{}), make(chan struct{})
	originalClock := blocked.clock
	_, e = blocked.worker.Submit(ctx, func() (any, error) {
		blocked.clock = func() time.Time { close(entered); <-release; return originalClock() }
		return nil, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	maintenanceDone := make(chan error, 1)
	go func() { _, e := r.MaintainPostingPacks(ctx, 1, "", false); maintenanceDone <- e }()
	<-entered
	other := threads[0]
	if other.owner == first.Board {
		other = threads[1]
	}
	readDone := make(chan error, 1)
	go func() { _, e := r.Thread(ctx, other.owner, other.key); readDone <- e }()
	select {
	case e = <-readDone:
	case <-time.After(5 * time.Second):
		e = fmt.Errorf("other board blocked")
	}
	close(release)
	if maintenanceErr := <-maintenanceDone; maintenanceErr != nil {
		t.Fatal(maintenanceErr)
	}
	_, restoreErr := blocked.worker.Submit(ctx, func() (any, error) { blocked.clock = originalClock; return nil, nil })
	if e != nil || restoreErr != nil {
		t.Fatal(e, restoreErr)
	}
	cursor := ""
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		report, e := r.MaintainPostingPacks(ctx, 1, cursor, true)
		if e != nil || len(report.Entries) != 1 {
			t.Fatal(report, e)
		}
		entry := report.Entries[0]
		id := maintenanceCursor(entry.Board, entry.Thread)
		if seen[id] || !entry.Pack.Applied || entry.Pack.Generation != 2 || entry.Decision.Level != 1 || entry.Reclaim.Files != 1 || !entry.Reclaim.Applied {
			t.Fatal(report)
		}
		seen[id] = true
		cursor = report.Next
	}
	if cursor != "" {
		t.Fatal("end cursor", cursor)
	}
	report, e := r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil || len(report.Entries) != 3 {
		t.Fatal(report, e)
	}
	for _, entry := range report.Entries {
		if entry.Decision.Compact || entry.Reclaim.Files != 0 {
			t.Fatal("idle repacked", entry)
		}
	}
	before, e := r.Thread(ctx, threads[0].owner, threads[0].key)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	after, e := r.Thread(ctx, threads[0].owner, threads[0].key)
	if e != nil || !samePublicSnapshot(before, after) {
		t.Fatal("restart", e)
	}
	// 時計がpack時刻より前へ戻っても再圧縮しない。保存levelを復元できる。
	report, e = r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range report.Entries {
		if entry.Decision.Compact || entry.Decision.Level != 1 {
			t.Fatal(entry)
		}
	}
	// 手動圧縮の後に残った旧世代も、圧縮要否とは独立して回収する。
	th := threads[0]
	if _, e = r.CompactThread(ctx, th.owner, th.key, 9, true); e != nil {
		t.Fatal(e)
	}
	report, e = r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, entry := range report.Entries {
		if entry.Board == th.owner {
			found = true
			if entry.Decision.Compact || entry.Decision.Level != 9 || entry.Reclaim.Files != 2 {
				t.Fatal(entry)
			}
		}
	}
	if !found {
		t.Fatal("missing thread")
	}
	b := r.posting[th.owner]
	_, e = b.worker.Submit(ctx, func() (any, error) {
		b.clock = func() time.Time { return time.Now().AddDate(1, 0, 0) }
		return nil, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	report, e = r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range report.Entries {
		if entry.Board == th.owner && (entry.Decision.Reason != "expired" || entry.Pack.Applied) {
			t.Fatal(entry)
		}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = r.MaintainPostingPacks(cancelCtx, 1, "", true); e == nil {
		t.Fatal("cancel ignored")
	}
	if _, e = r.MaintainPostingPacks(ctx, 0, "", true); e == nil {
		t.Fatal("invalid limit")
	}
}

func TestPackMaintenanceAdminAndLoop(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	client := newAdminClient(t, r)
	defer client.server.Close()
	for _, path := range []string{"/maintenance", "/api/v1/maintenance"} {
		res, _ := client.request("GET", path, "", nil)
		if res.StatusCode != 401 {
			t.Fatal(res.StatusCode)
		}
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := client.request("GET", "/maintenance", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "無効") || !strings.Contains(body, "未実行") {
		t.Fatal(res.StatusCode, body)
	}
	r.cfg.Maintenance = &PackMaintenanceConfig{Enabled: true, IntervalSeconds: 60, MaxThreads: 1}
	if r.ValidatePackMaintenance() == nil {
		t.Fatal("startup migration gate missing")
	}
	if _, e := r.EnablePostingPacks(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := r.ValidatePackMaintenance(); e != nil {
		t.Fatal(e)
	}
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	close(ticks)
	if e := r.runPackMaintenance(context.Background(), ticks, 1); e != nil {
		t.Fatal(e)
	}
	status := r.MaintenanceStatus()
	if status.Running || status.Failed || status.Completed == "" {
		t.Fatal(status)
	}
	res, body = client.request("GET", "/api/v1/maintenance", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `"running":false`) {
		t.Fatal(res.StatusCode, body)
	}
	r.maintenanceMu.Lock()
	if _, e := r.MaintainPostingPacks(context.Background(), 1, "", true); e == nil {
		t.Fatal("parallel maintenance")
	}
	r.maintenanceMu.Unlock()
}

func TestPackMaintenanceConfig(t *testing.T) {
	cfg := testConfig(t)
	for _, raw := range []string{`null`, `{"enabled":true,"interval_seconds":60,"max_threads":1}`, `{"enabled":false,"interval_seconds":86400,"max_threads":1000}`, `{"enabled":true,"interval_seconds":60,"max_threads":1,"max_seconds":300}`} {
		var m *PackMaintenanceConfig
		if e := json.Unmarshal([]byte(raw), &m); e != nil {
			t.Fatal(e)
		}
		cfg.Maintenance = m
		data, _ := json.Marshal(cfg)
		path := filepath.Join(t.TempDir(), "config.json")
		mustWrite(t, path, data)
		if _, e := LoadConfig(path); e != nil {
			t.Fatal(e)
		}
	}
	for _, m := range []PackMaintenanceConfig{{Enabled: true, IntervalSeconds: 59, MaxThreads: 1}, {Enabled: true, IntervalSeconds: 86401, MaxThreads: 1}, {IntervalSeconds: 60, MaxThreads: 0}, {Enabled: true, IntervalSeconds: 60, MaxThreads: 1001}, {IntervalSeconds: 60, MaxThreads: 1, MaxSeconds: -1}, {IntervalSeconds: 60, MaxThreads: 1, MaxSeconds: 301}} {
		cfg.Maintenance = &m
		if cfg.validate() == nil {
			t.Fatal("invalid accepted", m)
		}
	}
}
