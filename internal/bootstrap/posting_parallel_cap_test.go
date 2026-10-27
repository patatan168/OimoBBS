// 並行capture検証でも資格履歴・公開採番・正本復旧を維持することを実フォームで検査する。
package bootstrap

import (
	"fmt"
	"net/url"
	"oimobbs/internal/postcapture"
	"sync"
	"testing"
)

func TestParallelCaptureCapHistoryAndRecovery(t *testing.T) {
	cfg, initial := adminFixture(t)
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postcapture.Validate, PostingOptions{ParallelCaptureValidation: true})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "parallelcap", "資格の並行照合")
	if err != nil {
		t.Fatal(err)
	}
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	if admin.login(adminTestSecret) != 303 || admin.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	cap, secret := createTestCap(t, repo, admin, board.ID, []string{"create", "post"})
	server := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer server.Close()
	mail := "#cap:" + cap.ID.String() + ":" + secret
	created, err := sendForm(server, url.Values{"bbs": {"parallelcap"}, "subject": {"資格"}, "MESSAGE": {"最初"}, "mail": {mail}, "oimo_request_id": {"parallel-cap-create-01"}})
	if err != nil || !created.Accepted {
		t.Fatal(created, err)
	}
	results := make(chan formResult, 8)
	var pending sync.WaitGroup
	for i := 0; i < 8; i++ {
		pending.Go(func() {
			result, err := sendForm(server, url.Values{"bbs": {"parallelcap"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {fmt.Sprintf("返信%d", i)}, "mail": {mail}, "oimo_request_id": {fmt.Sprintf("parallel-cap-reply-%03d", i)}})
			if err != nil {
				t.Error(err)
			}
			results <- result
		})
	}
	pending.Wait()
	close(results)
	seen := map[uint32]bool{}
	for result := range results {
		if !result.Accepted || result.Duplicate || result.Number < 2 || result.Number > 9 || seen[result.Number] {
			t.Fatal("parallel cap reply", result)
		}
		seen[result.Number] = true
	}
	b := repo.posting[board.ID]
	if _, err = b.worker.Submit(t.Context(), func() (any, error) {
		if b.capCommitted[cap.ID] == 0 {
			t.Error("credential history missing")
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	server.Close()
	admin.server.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenPostingRepository(cfg, postcapture.Validate, PostingOptions{ParallelCaptureValidation: true})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	snapshot, err := recovered.Thread(t.Context(), board.ID, created.Key)
	if err != nil || snapshot == nil || snapshot.PostCount != 9 {
		t.Fatal("recovered cap replies", snapshot, err)
	}
	if recovered.posting[board.ID].capCommitted[cap.ID] == 0 {
		t.Fatal("recovered credential history missing")
	}
}
