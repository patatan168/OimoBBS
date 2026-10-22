// 投稿時間の窓・P99・停止/回復境界・標本上限を待ち時間なしで検証する。
package bootstrap

import (
	"context"
	"errors"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/store"
	"strings"
	"testing"
	"time"
)

func TestPostingLatencyThresholds(t *testing.T) {
	now := time.Unix(1700000000, 0)
	var s postingLatencyState
	for i := 0; i <= 60; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		s.add(at, 251*time.Millisecond)
		got := s.observe(at)
		if got.Paused != (i == 60) || got.P99Millis != 251 || !got.Known {
			t.Fatal(i, got)
		}
	}
	for i := 61; i <= 240; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		s.add(at, 149*time.Millisecond)
		got := s.observe(at)
		if got.Paused != (i < 240) {
			t.Fatal("recovery", i, got)
		}
	}
	for _, duration := range []time.Duration{250 * time.Millisecond, 250*time.Millisecond + 1} {
		var state postingLatencyState
		for i := 0; i <= 60; i++ {
			at := now.Add(time.Duration(i) * time.Second)
			state.add(at, duration)
			state.observe(at)
		}
		if state.paused != (duration > 250*time.Millisecond) {
			t.Fatal("exact high threshold", duration)
		}
	}
	s = postingLatencyState{paused: true}
	for i := 0; i <= 180; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		s.add(at, 150*time.Millisecond)
		if !s.observe(at).Paused {
			t.Fatal("recovered at 150ms")
		}
	}
}

func TestPostingLatencyWindowAndBounds(t *testing.T) {
	now := time.Unix(1700000000, 0)
	var s postingLatencyState
	for range 99 {
		s.add(now, time.Millisecond)
	}
	s.add(now, time.Second)
	if got := s.observe(now); got.P99Millis != 1 || got.Samples != 100 {
		t.Fatal(got)
	}
	if got := s.observe(now.Add(time.Minute)); got.Samples != 0 || got.P99Millis != 0 {
		t.Fatal("window end", got)
	}
	s = postingLatencyState{}
	for range latencySampleLimit + 1 {
		s.add(now, time.Millisecond)
	}
	if got := s.observe(now); got.Known || !got.Paused || got.Samples != latencySampleLimit {
		t.Fatal(got)
	}
	if got := s.observe(now.Add(-time.Second)); got.Known || !got.Paused {
		t.Fatal("rollback", got)
	}
	s = postingLatencyState{paused: true}
	for i := 0; i < 120; i++ {
		s.observe(now.Add(time.Duration(i) * time.Second))
	}
	if got := s.observe(now.Add(130 * time.Second)); !got.Paused || !got.Recovering {
		t.Fatal("gap recovered", got)
	}
}

func TestPostingLatencyAdmissionAndAdmin(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "latency", "投稿時間")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	fields := url.Values{"bbs": {"latency"}, "subject": {"圧縮延期"}, "MESSAGE": {"本文"}, "oimo_request_id": {"latency-create-0001"}}
	posted, e := sendForm(server, fields)
	if e != nil || !posted.Accepted {
		t.Fatal(posted, e)
	}
	if got := r.PostingLatency(); got.Samples != 1 {
		t.Fatal("accepted sample", got)
	}
	if _, e = sendForm(server, fields); e != nil {
		t.Fatal(e)
	}
	if got := r.PostingLatency(); got.Samples != 1 {
		t.Fatal("retry counted", got)
	}
	if _, e = r.EnablePostingPacks(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = r.CompactThread(ctx, info.ID, posted.Key, 0, true); e != nil {
		t.Fatal(e)
	}
	instant := time.Now()
	r.postingLatencyMu.Lock()
	r.postingLatency = postingLatencyState{paused: true}
	r.latencyClock = func() time.Time { return instant }
	r.postingLatencyMu.Unlock()
	release, e := r.reservePosting()
	if e != nil {
		t.Fatal("latency blocked posting", e)
	}
	release()
	if _, e = r.reservePack(); !errors.Is(e, app.ErrPackPressure) {
		t.Fatal(e)
	}
	report, e := r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil || len(report.Entries) != 1 || report.Entries[0].Deferred != "latency" || report.Entries[0].Pack.Applied || report.Entries[0].Reclaim.Files != 1 {
		t.Fatal(report, e)
	}
	if got := r.MaintenanceStatus(); got.LatencyDeferred != 1 || got.Deferred != 0 || got.Failed {
		t.Fatal(got)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, body := client.request("GET", "/maintenance", "", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "回復を確認中") || !strings.Contains(body, "投稿遅延で延期した圧縮</dt><dd>1") {
		t.Fatal(response.StatusCode, body)
	}
	for range 120 {
		instant = instant.Add(time.Second)
		r.PostingLatency()
	}
	report, e = r.MaintainPostingPacks(ctx, 10, "", true)
	if e != nil || !report.Entries[0].Pack.Applied {
		t.Fatal(report, e)
	}
}

func TestPostingLatencyExcludesNonCommit(t *testing.T) {
	r := &Repository{}
	for _, result := range []RepositoryPostingResult{{}, {PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.Durable}, Duplicate: true}}} {
		r.recordPostingLatency(time.Now(), result)
	}
	if got := r.PostingLatency(); got.Samples != 0 {
		t.Fatal(got)
	}
	r.recordPostingLatency(time.Now(), RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.Unknown}}})
	if got := r.PostingLatency(); got.Samples != 1 {
		t.Fatal(got)
	}
}
