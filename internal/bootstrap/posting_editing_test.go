// 未保存フォームを早く返しても、投稿成功と公開は三段の耐久保存後まで進まないことを検査する。
package bootstrap

import (
	"context"
	"errors"
	"net/http/httptest"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestEditingPreparationDoesNotWaitForPostingCommit(t *testing.T) {
	_, repo, info := postingRepositoryFixture(t)
	created := repo.Post(t.Context(), info.ID, 0, persistentFrame(t), []byte(`{"fixture":true}`))
	if created.Status != store.Durable {
		t.Fatal(created)
	}
	b := repo.posting[info.ID]
	frame := persistentReply(t, persistentFrame(t), time.Now())
	ready := make(chan editingForm, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	finished := make(chan []board.BatchResult, 1)
	go func() {
		value, err := b.worker.Submit(context.Background(), func() (any, error) {
			return b.runPostingBatch([]board.BatchOperation{
				{Context: t.Context(), Run: func() (any, error) {
					return b.postAdmitted(created.ThreadKey, frame, []byte(`{"fixture":true}`)), nil
				}},
				{Context: t.Context(), Run: func() (any, error) {
					return b.prepareEditing(created.ThreadKey, "web_reply", "", false)
				}, Complete: func(value any, err error) {
					if err == nil {
						ready <- value.(editingForm)
					}
				}},
				{Context: t.Context(), Run: func() (any, error) {
					<-release
					return legacyFailure(ErrPostingRequest), nil
				}},
			}), nil
		})
		if err != nil {
			t.Error(err)
			finished <- nil
			return
		}
		finished <- value.([]board.BatchResult)
	}()
	select {
	case form := <-ready:
		if form.csrf.Cookie == nil || form.csrf.Token == "" {
			t.Error("missing CSRF")
		}
	case <-time.After(5 * time.Second):
		t.Error("form blocked on posting commit")
	}
	snapshot, _ := b.publicSnapshot(created.ThreadKey, domain.Time(time.Now().UnixNano()))
	if snapshot == nil || snapshot.PostCount != 1 {
		t.Error("uncommitted reply became public")
	}
	select {
	case <-finished:
		t.Error("posting result completed before commit")
	default:
	}
	unblock()
	results := <-finished
	if len(results) != 3 {
		t.Fatal(results)
	}
	posted := results[0].Value.(RepositoryPostingResult)
	if posted.Status != store.Durable || posted.PostNumber != 2 || errors.Is(posted.Err, app.ErrPostingPrepared) {
		t.Fatal("posting did not wait for durable result", posted)
	}
}

func TestReplyFormSharesQueuedPostingBatch(t *testing.T) {
	cfg, repo, info := postingRepositoryFixture(t)
	create := persistentFrame(t)
	created := repo.Post(t.Context(), info.ID, 0, create, []byte(`{"fixture":true}`))
	if created.Status != store.Durable {
		t.Fatal(created)
	}
	b := repo.posting[info.ID]
	frame := persistentReply(t, create, time.Now())
	prepared, beforeCommit, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	original := b.postBatch.RunReady
	b.postBatch.RunReady = func(ops []board.BatchOperation, collect func() []board.BatchOperation) []board.BatchResult {
		collected := false
		return original(ops, func() []board.BatchOperation {
			if collected {
				close(beforeCommit)
				<-release
				return nil
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if added := collect(); len(added) > 0 {
					collected = true
					return added
				}
				runtime.Gosched()
			}
			return nil
		})
	}
	finished := make(chan any, 1)
	go func() {
		value, err := repo.submitPostingBatch(t.Context(), b, created.ThreadKey, func() (any, error) {
			close(prepared)
			return b.postAdmitted(created.ThreadKey, frame, []byte(`{"fixture":true}`)), nil
		})
		if err != nil {
			finished <- err
		} else {
			finished <- value
		}
	}()
	<-prepared
	formDone := make(chan struct{})
	writer := httptest.NewRecorder()
	request := httptest.NewRequest("GET", cfg.Public.BaseURL+"/web/post?key="+strconv.FormatUint(created.ThreadKey, 10), nil)
	go func() {
		defer close(formDone)
		repo.WebPostingHandler(info.ID, nil).ServeHTTP(writer, request)
	}()
	select {
	case <-beforeCommit:
	case <-time.After(6 * time.Second):
		t.Fatal("reply form split the pending posting batch")
	}
	select {
	case <-formDone:
	case <-time.After(5 * time.Second):
		t.Fatal("reply form waited for commit")
	}
	if writer.Code != 200 || pageFields(writer.Body.String()).Get("csrf") == "" {
		t.Error("missing form or CSRF", writer.Code)
	}
	snapshot, _ := b.publicSnapshot(created.ThreadKey, domain.Time(time.Now().UnixNano()))
	if snapshot == nil || snapshot.PostCount != 1 {
		t.Error("form exposed prepared reply")
	}
	unblock()
	value := <-finished
	result, ok := value.(RepositoryPostingResult)
	if !ok || result.Status != store.Durable || result.PostNumber != 2 {
		t.Fatal("posting result did not await commit", value)
	}
}
