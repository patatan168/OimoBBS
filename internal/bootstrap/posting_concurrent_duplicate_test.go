// 同一スレッドの並列返信と重複再送を実HTTPで流し、一括保存後も欠落・重複を防ぐ。
package bootstrap

import (
	"bytes"
	"fmt"
	"net/url"
	"oimobbs/internal/postcapture"
	"sync"
	"testing"
)

func TestPostingConcurrentHTTPDuplicate(t *testing.T) {
	cfg := testConfig(t)
	report, err := Initialize(cfg, "並列再送試験")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postcapture.Validate, PostingOptions{ParallelCaptureValidation: true})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	useHealthyPostingCapacity(t, repo)
	board, err := repo.CreateBoard(t.Context(), "parallelretry", "並列再送")
	if err != nil {
		t.Fatal(err)
	}
	server := formServer(t, repo, report.SiteID, board.ID)
	defer server.Close()
	first, err := sendForm(server, url.Values{"bbs": {"parallelretry"}, "subject": {"same thread"}, "MESSAGE": {"first"}, "oimo_request_id": {"parallel-retry-create-0001"}})
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	type outcome struct {
		index  int
		result formResult
		err    error
	}
	results := make(chan outcome, 64)
	var pending sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		pending.Go(func() {
			for i := worker; i < 64; i += 16 {
				pair := i / 2
				result, err := sendForm(server, url.Values{"bbs": {"parallelretry"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {fmt.Sprintf("parallel reply %02d", pair)}, "oimo_request_id": {fmt.Sprintf("parallel-retry-reply-%04d", pair)}})
				results <- outcome{i, result, err}
			}
		})
	}
	pending.Wait()
	close(results)
	numbers := map[int]uint32{}
	for row := range results {
		if row.err != nil || (!row.result.Accepted && !row.result.Duplicate) {
			t.Fatal(row.index, row.result, row.err)
		}
		pair := row.index / 2
		if n, ok := numbers[pair]; ok && n != row.result.Number {
			t.Fatal("duplicate changed number", pair, n, row.result.Number)
		}
		numbers[pair] = row.result.Number
	}
	snapshot, err := repo.Thread(t.Context(), board.ID, first.Key)
	if err != nil || snapshot == nil || snapshot.PostCount != 33 {
		t.Fatal("missing or duplicate durable reply", snapshot, err)
	}
	for i := 0; i < 32; i++ {
		if bytes.Count(snapshot.DAT, []byte(fmt.Sprintf("parallel reply %02d<>", i))) != 1 {
			t.Fatal("body count", i)
		}
	}
}
