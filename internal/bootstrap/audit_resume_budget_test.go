// snapshot後の監査照合が小さい予算でも前回位置から進み、完全な一覧へ到達することを検証する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// TestSnapshotAuditCatchUpBudgetMakesProgress は中断・取消・後続追記を挟んでも同じ一覧を復元する。
func TestSnapshotAuditCatchUpBudgetMakesProgress(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	installRuntimeFixture(t, cfg, repo, 12)
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		var site siteState
		if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			site.Name += "追記"
			if err := appendControl(repo.site, "site_name_update", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); err != nil {
				t.Fatal(err)
			}
		}
	}()
	query := auditQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Second), Limit: 200}
	want, err := collectAuditFixture(repo, context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	repo.auditIndex = nil // 再起動後の初回索引と同じ、保存済み証明だけがある状態。
	repo.mu.Unlock()
	done := false
	for attempt := 0; attempt < 10; attempt++ {
		budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 2}
		err = catchUpAuditFixture(repo, context.Background(), &budget)
		if err == nil {
			done = true
			t.Logf("snapshot audit resumed in %d bounded requests", attempt+1)
			break
		}
		if !errors.Is(err, store.ErrHistoryBudget) {
			t.Fatal(err)
		}
		if attempt == 0 {
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			budget = store.HistoryBudget{Bytes: 1 << 20, Frames: 2}
			if err := catchUpAuditFixture(repo, canceled, &budget); !errors.Is(err, context.Canceled) {
				t.Fatal("canceled continuation", err)
			}
			want = append([]AuditEntry{appendAuditResumeTail(t, repo)}, want...)
		}
	}
	if !done {
		t.Fatal("snapshot audit verification restarted from the beginning on every request", err)
	}
	query.To = time.Now().Add(time.Second)
	got, err := collectAuditFixture(repo, context.Background(), query)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("resumed audit differs", len(want), len(got), err)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, page, body := client.audit(url.Values{"from": {query.From.Format(time.RFC3339Nano)}, "limit": {"200"}}.Encode())
	if response.StatusCode != 200 || !reflect.DeepEqual(want, page.Entries) {
		t.Fatal("resumed HTTP audit", response.StatusCode, body)
	}
}

// appendAuditResumeTail は照合中の証明範囲より後へ実操作を足し、独立に期待要約を作る。
func appendAuditResumeTail(t *testing.T, repo *Repository) AuditEntry {
	t.Helper()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	state := repo.site.State()
	frame, err := controlFrame(state, domain.NewID(), domain.Time(time.Now().UnixNano()), "site_name_update", []store.Mutation{mutation("site", "state", state.Rows["site:state"].Value, nil)}, []string{})
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := store.ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	var operation store.ControlOperation
	if err := json.Unmarshal(decoded.Records[0].JSON, &operation); err != nil {
		t.Fatal(err)
	}
	entry, ok := auditSummary(siteID(state), "site", decoded.Records[0], operation)
	if !ok {
		t.Fatal("missing expected summary")
	}
	if result := repo.site.Append(frame); result.Status != store.Durable {
		t.Fatal(result)
	}
	return entry
}
