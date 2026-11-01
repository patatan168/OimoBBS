// 共有参照によるページ送りが期限回収・表示分類の解放で変化せず、保持予算を守ることを確認する。
package bootstrap

import (
	"context"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestAuditSnapshotSurvivesIndexPruning(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	importCandidateAudit(t, repo)
	repo.mu.Lock()
	owner := siteID(repo.site.State())
	expired := &auditIndexedEntry{entry: AuditEntry{Owner: owner, ID: domain.NewID(), Action: "other_admin_operation"}, at: time.Now().Add(-auditRetention - time.Hour), bytes: 500}
	current := &auditIndexedEntry{entry: AuditEntry{Owner: owner, ID: domain.NewID(), Action: "site_name_update"}, at: time.Now(), bytes: 500}
	snapshot := []auditSnapshotRow{{expired, "software_update_request"}, {current, "site_name_update"}}
	identity := auditIdentity{owner, expired.entry.ID}
	repo.auditIndex.days["fixture"] = []*auditIndexedEntry{expired, current}
	repo.auditIndex.count += 2
	repo.auditIndex.bytes += 1000
	repo.auditIndex.rememberOperation(expired.entry, "software_update_request")
	repo.mu.Unlock()
	budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	if err := catchUpAuditFixture(repo, context.Background(), &budget); err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if _, exists := repo.auditIndex.details[identity]; exists {
		t.Fatal("expired display classification retained")
	}
	if rows := repo.auditIndex.days["fixture"]; len(rows) != 1 || rows[0] != current {
		t.Fatal("expired index entry not pruned")
	}
	if entry := snapshot[0].summary(); entry.ID != expired.entry.ID || entry.Action != "software_update_request" {
		t.Fatal("fixed snapshot changed after pruning", entry)
	}
	if snapshot[1].summary().ID != current.entry.ID {
		t.Fatal("index compaction changed fixed snapshot")
	}
}

func TestAuditSnapshotBudgetSharesRecords(t *testing.T) {
	shared := &auditIndexedEntry{bytes: 48 << 20}
	second := &auditIndexedEntry{bytes: 48 << 20}
	third := &auditIndexedEntry{bytes: 48 << 20}
	existing := map[string]auditSnapshot{"first": {rows: []auditSnapshotRow{{record: shared}}}, "second": {rows: []auditSnapshotRow{{record: shared}}}}
	if !auditSnapshotsFit(existing, []auditSnapshotRow{{record: shared}}) {
		t.Fatal("shared entries counted once per snapshot")
	}
	if auditSnapshotsFit(existing, []auditSnapshotRow{{record: second}, {record: third}}) {
		t.Fatal("distinct retained entries exceeded 128MiB")
	}
}
