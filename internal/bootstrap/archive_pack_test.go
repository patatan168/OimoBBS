// 現行Zstandardだけで保存し、再起動後の無変更再圧縮抑止を実保存で検証する。
package bootstrap

import (
	"net/url"
	"oimobbs/internal/postcapture"
	"testing"
)

func TestArchiveMaintenanceRestart(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() {
		if r != nil {
			r.Close()
		}
	}()
	ctx := t.Context()
	board, err := r.CreateBoard(ctx, "archive", "保存圧縮")
	if err != nil {
		t.Fatal(err)
	}
	server := formServer(t, r, siteID(r.site.State()), board.ID)
	created, err := sendForm(server, url.Values{"bbs": {"archive"}, "subject": {"archive"}, "MESSAGE": {"UNCHANGED PUBLIC BODY"}, "oimo_request_id": {"archive-create-0001"}})
	server.Close()
	if err != nil || !created.Accepted {
		t.Fatal(created, err)
	}
	if _, err = r.EnablePostingPacks(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := r.Thread(ctx, board.ID, created.Key)
	if err != nil {
		t.Fatal(err)
	}
	b := r.posting[board.ID]
	_, err = b.worker.Submit(ctx, func() (any, error) { return b.threads[created.Key].CompactWithClock(ctx, b.clock, 6, true) })
	if err != nil {
		t.Fatal(err)
	}
	report, err := r.MaintainPostingPacks(ctx, 5, "", true)
	if err != nil || len(report.Entries) != 1 || report.Entries[0].Decision.Compact || report.Entries[0].Pack.Applied {
		t.Fatal(report, err)
	}
	after, err := r.Thread(ctx, board.ID, created.Key)
	if err != nil || !samePublicSnapshot(before, after) {
		t.Fatal("changed public data", err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	report, err = r.MaintainPostingPacks(ctx, 5, "", true)
	if err != nil || len(report.Entries) != 1 || report.Entries[0].Decision.Compact || report.Entries[0].Pack.Applied {
		t.Fatal("unnecessary recompression after restart", report, err)
	}
}
