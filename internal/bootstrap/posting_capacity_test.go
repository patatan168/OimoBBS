// 投稿容量の境界・回復待ち・保存前拒否・受理済み再送を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"strings"
	"testing"
	"time"
)

// useHealthyPostingCapacity は容量以外の統合試験を実行環境のディスク使用率から独立させる。
// HTTP受付やワーカーを起動する前に呼ぶ。予約・拒否・回復待ちの本体処理はそのまま使う。
func useHealthyPostingCapacity(t *testing.T, repo *Repository) {
	t.Helper()
	repo.packResourcesMu.Lock()
	defer repo.packResourcesMu.Unlock()
	repo.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 2 << 30}, nil
	}
}

func TestPostingCapacityRecovery(t *testing.T) {
	now := time.Unix(1700000000, 0)
	low := platform.DiskSpace{Total: 2 << 30, Available: (1 << 30) + postingReservationBytes - 1}
	high := platform.DiskSpace{Total: 2 << 30, Available: (1 << 30) + (256 << 20) + postingReservationBytes}
	var s postingCapacityState
	exact := low
	exact.Available++
	s.observe(exact, 0, now, nil)
	if !s.status.WriteReady {
		t.Fatal("exact threshold")
	}
	s.observe(low, 0, now, nil)
	if s.status.WriteReady {
		t.Fatal("low accepted")
	}
	for i := 0; i < 30; i++ {
		s.observe(high, 0, now.Add(time.Duration(i)*time.Second), nil)
		if s.status.WriteReady {
			t.Fatal("early recovery", i)
		}
	}
	s.observe(high, 0, now.Add(30*time.Second), nil)
	if !s.status.WriteReady {
		t.Fatal("recovery")
	}
	s.observe(high, 0, now.Add(31*time.Second), errors.New("probe"))
	if s.status.Known || s.status.WriteReady {
		t.Fatal("probe failure")
	}
	s.observe(high, 0, now.Add(32*time.Second), nil)
	s.observe(high, 0, now.Add(62*time.Second), nil)
	if s.status.WriteReady {
		t.Fatal("observation gap")
	}
	s.observe(high, 0, now.Add(61*time.Second), nil)
	if s.status.WriteReady {
		t.Fatal("backward clock")
	}
	s.observe(high, high.Available, now.Add(63*time.Second), nil)
	if s.status.WriteReady || s.status.Recovering {
		t.Fatal("reserved capacity")
	}
}

func TestPostingCapacityRejectsBeforePersistence(t *testing.T) {
	_, r := adminFixture(t)
	useHealthyPostingCapacity(t, r)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "capacity", "容量")
	if e != nil {
		t.Fatal(e)
	}
	observer, e := evidence.NewHTTPObserver(siteID(r.site.State()), domain.NewID(), "capacity-test")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		result, _ := r.routeLegacyPost(request, observer)
		if result.Confirmation != nil {
			http.SetCookie(w, &http.Cookie{Name: "oimo_confirm", Value: result.Confirmation.Token})
		}
		if result.Status != store.Durable && result.Confirmation == nil && !errors.Is(result.Err, ErrPostingCapacity) {
			t.Errorf("unexpected rejection: %v", result.Err)
		}
		json.NewEncoder(w).Encode(formResult{result.ThreadKey, result.PostNumber, result.Duplicate, result.Status == store.Durable, result.Confirmation})
	}))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	fields := url.Values{"bbs": {"capacity"}, "subject": {"容量"}, "MESSAGE": {"first"}, "oimo_request_id": {"capacity-create-001"}}
	first, e := sendForm(server, fields)
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	now := time.Now()
	r.capacityClock = func() time.Time { return now }
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 1 << 30}, nil
	}
	before := r.boards[info.ID].State().Seq
	reply := url.Values{"bbs": {"capacity"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"second"}, "oimo_request_id": {"capacity-reply-0001"}}
	rejected, e := sendForm(server, reply)
	if e != nil || rejected.Accepted {
		t.Fatal(rejected, e)
	}
	newThread := url.Values{"bbs": {"capacity"}, "subject": {"拒否"}, "MESSAGE": {"new"}, "oimo_request_id": {"capacity-create-002"}}
	rejected, e = sendForm(server, newThread)
	if e != nil || rejected.Accepted {
		t.Fatal(rejected, e)
	}
	if after := r.boards[info.ID].State().Seq; before != after {
		t.Fatal("key reservation changed")
	}
	retry, e := sendForm(server, fields)
	if e != nil || !retry.Duplicate || retry.Key != first.Key {
		t.Fatal(retry, e)
	}
	snap, e := r.Thread(ctx, info.ID, first.Key)
	if e != nil || snap.PostCount != 1 {
		t.Fatal(snap, e)
	}
	if r.postReserved != 0 {
		t.Fatal("reservation leak")
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 2 << 30}, nil
	}
	for i := 0; i <= 30; i++ {
		r.PostingCapacity()
		now = now.Add(time.Second)
	}
	accepted, e := sendForm(server, reply)
	if e != nil || !accepted.Accepted || accepted.Number != 2 {
		t.Fatal(accepted, e)
	}
	if r.postReserved != 0 {
		t.Fatal("reservation leak after success")
	}
}

// TestPostingCapacityAdmin は停止・回復待ち・受付中を認証済みHTTPで表示できることを確認する。
func TestPostingCapacityAdmin(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	now := time.Now()
	r.capacityClock = func() time.Time { return now }
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 1 << 30}, nil
	}
	response, body := client.request("GET", "/maintenance", "", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "確認不能のため停止中") {
		t.Fatal(response.StatusCode, body)
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 2 << 30}, nil
	}
	_, body = client.request("GET", "/maintenance", "", nil)
	if !strings.Contains(body, "容量回復を確認中") {
		t.Fatal(body)
	}
	for range 30 {
		now = now.Add(time.Second)
		r.PostingCapacity()
	}
	_, body = client.request("GET", "/api/v1/maintenance", "", nil)
	if !strings.Contains(body, `"write_ready":true`) {
		t.Fatal(body)
	}
}
