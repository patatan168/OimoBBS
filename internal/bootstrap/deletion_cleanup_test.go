// 削除版packへの物理切替・途中停止の再開・容量延期・再送拒否を実保存先で検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestRedactionPhysicalCleanupRecovery(t *testing.T) {
	for _, stop := range []string{"", "cleanup:task_pending", "cleanup:cleaning", "cleanup:task_running", "cleanup:pack", "cleanup:old_files", "cleanup:copy_complete", "capacity"} {
		t.Run(stop, func(t *testing.T) {
			cfg, repo := adminFixture(t)
			if _, err := repo.EnablePostingPacks(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = repo.Close() }()
			info, e := repo.CreateBoard(context.Background(), "clean", "掃除")
			if e != nil {
				t.Fatal(e)
			}
			form := formServer(t, repo, siteID(repo.site.State()), info.ID)
			defer form.Close()
			fields := url.Values{"bbs": {"clean"}, "subject": {"cleanup-title"}, "MESSAGE": {"cleanup-original-private-body"}, "oimo_request_id": {"cleanup-create-0001"}}
			created, e := sendForm(form, fields)
			if e != nil || !created.Accepted {
				t.Fatal(created, e)
			}
			admin := newAdminClient(t, repo)
			defer admin.server.Close()
			if admin.login(adminTestSecret) != 303 {
				t.Fatal("login")
			}
			path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", info.ID, created.Key)
			res, _ := admin.request("GET", path, "", nil)
			headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"cleanup-request-0001"}}
			raw, _ := json.Marshal(AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}})
			res, body := admin.request("POST", path, string(raw), headers)
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode, body)
			}
			b := repo.posting[info.ID]
			_, e = b.worker.Submit(context.Background(), func() (any, error) {
				b.deletionCheckpoint = func(stage string) error {
					if stage == stop {
						return errors.New("simulated cleanup shutdown")
					}
					return nil
				}
				if stop == "capacity" {
					b.reserveDeletionPack = func() (func(), error) { return nil, app.ErrPackCapacity }
				}
				return nil, b.cleanRedactions(8)
			})
			if (e != nil) != (stop != "" && stop != "capacity") {
				t.Fatal("checkpoint", e)
			}
			if stop == "capacity" {
				res, body = admin.request("GET", path, "", nil)
				if res.StatusCode != 200 || !strings.Contains(body, `"state":"failed"`) || !strings.Contains(body, `"last_error":"capacity"`) {
					t.Fatal(res.StatusCode, body)
				}
			}
			form.Close()
			admin.server.Close()
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			b = repo.posting[info.ID]
			_, e = b.worker.Submit(context.Background(), func() (any, error) { return nil, b.cleanRedactions(8) })
			if e != nil {
				t.Fatal(e)
			}
			dir := filepath.Join(cfg.DataDir, "boards", info.ID.String(), "threads", fmt.Sprint(created.Key))
			manifest, _, e := store.InspectThreadFiles(dir)
			if e != nil || manifest.Base == nil || manifest.Base.Seq != 2 {
				t.Fatal(manifest, e)
			}
			files, e := os.ReadDir(dir)
			if e != nil || len(files) != 3 {
				t.Fatal("old generations retained", files, e)
			}
			packed, e := os.ReadFile(filepath.Join(dir, manifest.Base.File))
			if e != nil {
				t.Fatal(e)
			}
			pack, e := store.DecodePack(packed)
			if e != nil || pack.State.Posts[0].Body != "あぼーん" || strings.Contains(string(pack.State.Lines[0]), "cleanup-original-private-body") {
				t.Fatal("old body retained in pack", e)
			}
			snapshot, e := repo.Thread(context.Background(), info.ID, created.Key)
			if e != nil || snapshot == nil || snapshot.Revision != 2 || strings.Contains(string(snapshot.DAT), "cleanup-original-private-body") {
				t.Fatal(snapshot, e)
			}
			form = formServer(t, repo, siteID(repo.site.State()), info.ID)
			defer form.Close()
			retry, e := sendForm(form, fields)
			if e != nil || retry.Accepted {
				t.Fatal("deleted create accepted after body recovery", retry, e)
			}
			admin = newAdminClient(t, repo)
			defer admin.server.Close()
			if admin.login(adminTestSecret) != 303 {
				t.Fatal("login")
			}
			res, body = admin.request("GET", path, "", nil)
			if res.StatusCode != 200 || !strings.Contains(body, `"state":"complete"`) || !strings.Contains(body, `"phase":"cleaning"`) {
				t.Fatal(res.StatusCode, body)
			}
			res, body = admin.request("POST", path, string(raw), headers)
			if res.StatusCode == 200 {
				t.Fatal("old-session CSRF accepted")
			}
			// 後日の圧縮による旧削除版は、コピー完了の復旧を妨げない。
			if _, e := repo.CompactThread(context.Background(), info.ID, created.Key, 9, true); e != nil {
				t.Fatal(e)
			}
			form.Close()
			admin.server.Close()
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("completed copy rejected later compaction", e)
			}
		})
	}
}

func TestCopyTaskRequiresDeletionBinding(t *testing.T) {
	id := domain.NewID()
	task := DeletionCopyTask{ID: id, Deletion: id, Kind: "base_delta", CopyID: "thread:1", State: "pending", ExpectedDigest: [32]byte{1}}
	raw, _ := json.Marshal(task)
	if e := validateDeletionCopyTask(id.String(), nil, raw); e != nil {
		t.Fatal(e)
	}
	state := store.ControlState{Rows: map[string]store.ControlRow{"copy_task:" + id.String(): {Value: raw}}}
	if e := validateDeletionTasks(state, 1); e == nil {
		t.Fatal("orphan task accepted")
	}
	var decoded DeletionCopyTask
	if e := strictjson.Decode(raw, &decoded); e != nil {
		t.Fatal(e)
	}
}

func TestCleanupBatchDoesNotStarveLaterTasks(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	info, e := repo.CreateBoard(context.Background(), "fair", "巡回")
	if e != nil {
		t.Fatal(e)
	}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID)
	defer form.Close()
	created, e := sendForm(form, url.Values{"bbs": {"fair"}, "subject": {"cleanup-title"}, "MESSAGE": {"original-body"}, "oimo_request_id": {"fair-create-0001"}})
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", info.ID, created.Key)
	for n, hideTitle := range []bool{false, true} {
		res, _ := admin.request("GET", path, "", nil)
		headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {fmt.Sprintf("fair-cleanup-request-%04d", n)}}
		raw, _ := json.Marshal(AdminModeration{Kind: "redact", HideTitle: hideTitle, Ranges: []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}})
		res, body := admin.request("POST", path, string(raw), headers)
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
	}
	b := repo.posting[info.ID]
	_, e = b.worker.Submit(context.Background(), func() (any, error) {
		reserve := b.reserveDeletionPack
		b.reserveDeletionPack = func() (func(), error) {
			if b.redactionCleanupAfter == fmt.Sprintf("%020d/%020d", created.Key, 1) {
				return nil, app.ErrPackCapacity
			}
			return reserve()
		}
		defer func() { b.reserveDeletionPack = reserve }()
		for range 2 {
			if e := b.cleanRedactions(1); e != nil {
				return nil, e
			}
		}
		failed, completed := 0, 0
		for name, row := range b.deletions[created.Key].State().Rows {
			if !strings.HasPrefix(name, "copy_task:") {
				continue
			}
			var task DeletionCopyTask
			if e := strictjson.Decode(row.Value, &task); e != nil {
				return nil, e
			}
			if task.State == "failed" {
				failed++
			}
			if task.State == "complete" {
				completed++
			}
		}
		if failed != 1 || completed != 1 {
			return nil, fmt.Errorf("failed task starved next batch: failed=%d complete=%d", failed, completed)
		}
		return nil, nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
