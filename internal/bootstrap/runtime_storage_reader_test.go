// 有効済み形式の保守再開と、snapshot用の完全な監査照合を別の契約として検証する。
package bootstrap

import (
	"context"
	"errors"
	"testing"

	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func TestRuntimeStorageReaderReopenWithoutAuditRescan(t *testing.T) {
	cfg, repo := adminFixture(t)
	if _, err := repo.enableStorageReader(t.Context(), 99, "runtime_reader_fixture"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	before := repo.site.State().Seq
	if err := repo.ensureRuntimeStorageReader(t.Context(), 99, "runtime_reader_fixture"); err != nil {
		t.Fatal(err)
	}
	if repo.site.State().Seq != before || repo.auditIndex != nil {
		t.Fatal("enabled runtime format rescanned or changed controls")
	}
	if err := repo.EnableStoragePressureReclamation(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := repo.TransferThreadAudits(t.Context(), 8); err != nil {
		t.Fatal(err)
	}
	if !repo.pressureEnabled.Load() || repo.auditIndex != nil {
		t.Fatal("maintenance restart required a full audit scan")
	}
	// 有効済みでも、明示したsnapshot用の有効化は完全照合を省略しない。
	report, err := repo.EnableControlSnapshots(t.Context())
	if err != nil || !report.AuditComplete || repo.auditIndex == nil {
		t.Fatal(report, err)
	}
}

func TestRuntimeStorageReaderAdvancesWithAudit(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	if err := repo.ensureRuntimeStorageReader(t.Context(), 99, "runtime_reader_fixture"); err != nil {
		t.Fatal(err)
	}
	var site siteState
	if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != 99 {
		t.Fatal(site.MinimumReader, err)
	}
	if report, err := repo.VerifyAuditTransfer(t.Context()); err != nil || !report.Complete {
		t.Fatal(report, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := repo.ensureRuntimeStorageReader(ctx, 99, "runtime_reader_fixture"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled activation", err)
	}
}
