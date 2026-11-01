// 原本整理の旧進捗・新しい再開位置が一覧を増やさず、保存証明とsnapshot再開を維持することを検証する。
package bootstrap

import (
	"context"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

// TestAdminAuditGCCheckpoints は実HTTPの一覧・件数・検索候補と、旧要約の検証・snapshot再開を照合する。
func TestAdminAuditGCCheckpoints(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	if err := repo.EnableRequiredOriginalReclamation(t.Context()); err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, before, body := client.audit("")
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	for _, reason := range []string{"required_original_gc_progress", requiredGCCheckpoint} {
		for range 32 {
			job := requiredGCJobForTest(t, repo)
			job.At = domain.Time(time.Now().UnixNano())
			repo.mu.Lock()
			err := repo.saveRequiredGCJob(job, reason)
			repo.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := repo.DisableRequiredOriginalReclamation(t.Context()); err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		response, page, body := client.audit("limit=200")
		if response.StatusCode != 200 || page.Total != before.Total+1 {
			t.Fatal("internal progress inflated total", response.StatusCode, before.Total, page.Total, body)
		}
		if len(page.Entries) == 0 || page.Entries[0].Action != "required_original_gc_configure" {
			t.Fatal("configuration change was hidden", page)
		}
		for _, entry := range page.Entries {
			if entry.Action == "required_original_gc_progress" || entry.Action == requiredGCCheckpoint {
				t.Fatal("internal progress exposed", entry)
			}
		}
		response, html := client.request("GET", "/audit", "", nil)
		if response.StatusCode != 200 || strings.Contains(html, "原本ログの自動整理の進捗を記録") || strings.Contains(html, `value="required_original_gc_progress"`) {
			t.Fatal("internal progress in HTML or action picker", response.StatusCode, html)
		}
		response, hidden, body := client.audit("action=required_original_gc_progress")
		if response.StatusCode != 200 || hidden.Total != 0 || hidden.Next != "" {
			t.Fatal("legacy action filter exposed progress", response.StatusCode, body)
		}
		if report, err := repo.VerifyAuditTransfer(context.Background()); err != nil || !report.Complete {
			t.Fatal("audit proof changed", report, err)
		}
		repo.mu.Lock()
		_, entries, err := repo.loadAuditProof(t.Context(), siteID(repo.site.State()), "site", newArchiveBudget())
		count := repo.auditIndex.count
		repo.mu.Unlock()
		if err != nil || count != int(page.Total) {
			t.Fatal("index includes hidden progress", count, page.Total, err)
		}
		legacy := 0
		for _, entry := range entries {
			if entry.Summary.Action == "required_original_gc_progress" {
				legacy++
			}
			if entry.Summary.Action == requiredGCCheckpoint {
				t.Fatal("new checkpoint copied into daily audit")
			}
		}
		if legacy != 32 || len(entries) != int(page.Total)+legacy {
			t.Fatal("old summaries changed or new checkpoints archived", legacy, len(entries), page.Total)
		}
		if attempt == 0 {
			client.server.Close()
			installRuntimeFixture(t, cfg, repo, 12)
			repo, err = OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal(err)
			}
			client = newAdminClient(t, repo)
			if client.login(adminTestSecret) != 303 {
				t.Fatal("relogin")
			}
		}
	}
	if job := requiredGCJobForTest(t, repo); job.Enabled {
		t.Fatal("GC configuration did not survive restart", job)
	}
}

// TestRequiredGCProgressStaysInternal は実際の原本回収が新しい内部保存名で進み、再開位置を保持することを確認する。
func TestRequiredGCProgressStaysInternal(t *testing.T) {
	_, repo, _, _, _, _ := requiredReclaimRepositoryFixture(t, true)
	if err := repo.EnableRequiredOriginalReclamation(t.Context()); err != nil {
		t.Fatal(err)
	}
	if removed, err := repo.SweepRequiredOriginals(t.Context()); err != nil || removed != 2 {
		t.Fatal("original reclamation", removed, err)
	}
	job := requiredGCJobForTest(t, repo)
	if job.Board == nil || job.Proof == (domain.Hash{}) || job.Day == 0 {
		t.Fatal("progress was not saved", job)
	}
	rows, err := collectAuditFixture(repo, t.Context(), auditQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range rows {
		if entry.Action == "required_original_gc_progress" || entry.Action == requiredGCCheckpoint {
			t.Fatal("actual GC produced progress summary", entry)
		}
	}
	if report, err := repo.VerifyAuditTransfer(t.Context()); err != nil || !report.Complete {
		t.Fatal(report, err)
	}
}
