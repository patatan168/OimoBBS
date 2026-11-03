// 起動時の監査照合が予算をまたいで完了し、破損・取消・進捗なしを拒否することを確認する。
package bootstrap

import (
	"context"
	"errors"
	"testing"

	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// TestStartupSnapshotAuditBudget はsnapshot後の実操作を小さい予算で最後まで照合する。
func TestStartupSnapshotAuditBudget(t *testing.T) {
	cfg, repo := adminFixture(t)
	installRuntimeFixture(t, cfg, repo, 12)
	repo, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	repo.mu.Lock()
	var site siteState
	err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site)
	for i := 0; i < 8 && err == nil; i++ {
		site.Name += "追記"
		err = appendControl(repo.site, "site_name_update", []store.Mutation{mutation("site", "state", site, nil)}, []string{})
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	importCandidateAudit(t, repo)
	owner := siteID(repo.site.State())
	archiveBudget := int64(64 << 20)
	proof, entries, err := repo.loadAuditProof(t.Context(), owner, "site", &archiveBudget)
	if err != nil || proof == nil {
		t.Fatal(err)
	}
	anchor := repo.anchors[owner]
	limit := store.HistoryBudget{Bytes: 1 << 20, Frames: 2}
	one := limit
	if _, err := verifySnapshotAudit(t.Context(), repo.site, anchor, *proof, entries, &one); !errors.Is(err, store.ErrHistoryBudget) {
		t.Fatal("fixture did not exceed one scan budget", err)
	}
	result, err := verifyStartupSnapshotAudit(t.Context(), repo.site, anchor, *proof, entries, limit)
	if err != nil || !result.Complete || result.VerifiedSeq != repo.site.State().Seq {
		t.Fatal("startup verification did not finish", result, err)
	}
	for _, empty := range []store.HistoryBudget{{Frames: 2}, {Bytes: 1 << 20}} {
		if _, err := verifyStartupSnapshotAudit(t.Context(), repo.site, anchor, *proof, entries, empty); !errors.Is(err, store.ErrHistoryBudget) {
			t.Fatal("no-progress budget was accepted", err)
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := verifyStartupSnapshotAudit(canceled, repo.site, anchor, *proof, entries, limit); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was ignored", err)
	}
	broken := *proof
	broken.SourceHash[0] ^= 1
	if _, err := verifyStartupSnapshotAudit(t.Context(), repo.site, anchor, broken, entries, limit); err == nil || errors.Is(err, store.ErrHistoryBudget) {
		t.Fatal("corrupt proof was not rejected after continuation", err)
	}
}

// TestStartupAuditVerificationHandoff は検証済みsnapshotを最初の監査取得で再走査しないことを確認する。
func TestStartupAuditVerificationHandoff(t *testing.T) {
	cfg, repo := adminFixture(t)
	installRuntimeFixture(t, cfg, repo, 12)
	repo, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if len(repo.auditVerified) == 0 {
		t.Fatal("startup verification was discarded")
	}
	budget := store.HistoryBudget{}
	if err := catchUpAuditFixture(repo, t.Context(), &budget); err != nil {
		t.Fatal("verified prefix was scanned again", err)
	}
	if len(repo.auditVerified) != 0 || repo.auditIndex.count == 0 {
		t.Fatal("verified entries were not handed to the audit index")
	}
}
