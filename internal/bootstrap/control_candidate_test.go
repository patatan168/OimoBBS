// 稼働正本を変更しないスナップショット候補の作成・照合・不完全結果を検証する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// collectAuditFixture は稼働中の所有列と同じmutexを取得して監査を照会する。
func collectAuditFixture(r *Repository, ctx context.Context, q auditQuery) ([]AuditEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.collectAudit(ctx, q)
}

// catchUpAuditFixture はバックグラウンド更新と競合しない境界で試験用の取込を進める。
func catchUpAuditFixture(r *Repository, ctx context.Context, budget *store.HistoryBudget) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.catchUpAudit(ctx, budget)
}

func importCandidateAudit(t *testing.T, r *Repository) {
	t.Helper()
	if _, e := collectAuditFixture(r, context.Background(), auditQuery{From: time.Now().Add(-24 * time.Hour), To: time.Now().Add(time.Second), Limit: 200}); e != nil {
		t.Fatal(e)
	}
}
func candidateParent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return dir
}

func TestControlCandidateRoundTripAndStale(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	board, e := r.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	// 初期値以外の板設定とスレッドキー高水位も、初期作成の検証を緩めず保存する。
	res, v := client.board(board.ID.String())
	edit := v.Settings
	edit.Input.Noname = "変更した名無し"
	raw, _ := json.Marshal(edit)
	res, body := client.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(raw), candidateHeaders(res.Header.Get("ETag"), res.Header.Get("X-CSRF-Token")))
	if res.StatusCode != 200 {
		t.Fatal(body)
	}
	if e = appendControl(r.boards[board.ID], "reserve_thread_key", []store.Mutation{mutation("key_watermark", "thread", map[string]domain.U64{"last_reserved_key": 123}, nil)}, []string{}); e != nil {
		t.Fatal(e)
	}
	importCandidateAudit(t, r)
	before, e := os.ReadFile(filepath.Join(cfg.DataDir, "site", "control-000001.wal"))
	if e != nil {
		t.Fatal(e)
	}
	for _, level := range []int{0, 1, 6, 9} {
		dir := filepath.Join(candidateParent(t), "candidate")
		result, e := r.PrepareControlSnapshot(context.Background(), dir, level)
		if e != nil || !result.Verified || result.Activated || result.Owners != 2 {
			t.Fatal(result, e)
		}
		got, e := r.VerifyControlSnapshot(context.Background(), dir)
		if e != nil || got != result {
			t.Fatal(got, e)
		}
		if _, e = r.PrepareControlSnapshot(context.Background(), dir, level); e == nil {
			t.Fatal("overwritten")
		}
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			info, _ := entry.Info()
			if info.Mode().Perm() != 0600 {
				t.Fatal("file mode", info.Mode())
			}
		}
		// 保存byteを変更した候補は照合を拒否する。
		if level == 0 {
			manifest, err := readCandidateManifest(dir)
			if err != nil {
				t.Fatal(err)
			}
			item := manifest.Owners[1]
			original := r.boards[board.ID].State()
			for _, field := range []string{"revision", "expires"} {
				altered := store.ControlState{Seq: original.Seq, Rows: map[string]store.ControlRow{}}
				for key, row := range original.Rows {
					altered.Rows[key] = row
				}
				row := altered.Rows["key_watermark:thread"]
				if field == "revision" {
					row.Revision = 1
				} else {
					expires := domain.Time(time.Now().UnixNano())
					row.Expires = &expires
				}
				altered.Rows["key_watermark:thread"] = row
				changed, err := store.EncodeControlSnapshot(item.header(), altered, level, snapshotValues(item.Kind))
				if err != nil {
					t.Fatal(err)
				}
				item.Length = domain.U64(len(changed))
				item.SHA = sha256.Sum256(changed)
				manifest.Owners[1] = item
				body, _ := json.Marshal(manifest)
				if err = os.WriteFile(filepath.Join(dir, item.File), changed, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "candidate.json"), body, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err = r.VerifyControlSnapshot(context.Background(), dir); err == nil {
					t.Fatal("changed row metadata accepted", field)
				}
			}
		}
		if level == 6 {
			manifest, e := readCandidateManifest(dir)
			if e != nil {
				t.Fatal(e)
			}
			owner := manifest.Owners[1]
			file := filepath.Join(dir, owner.File)
			data, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			data[len(data)-1] ^= 1
			if e = os.WriteFile(file, data, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e = r.VerifyControlSnapshot(context.Background(), dir); e == nil {
				t.Fatal("corrupt snapshot accepted")
			}
		}
	}
	after, _ := os.ReadFile(filepath.Join(cfg.DataDir, "site", "control-000001.wal"))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("source mutated")
	}
	stale := filepath.Join(candidateParent(t), "stale")
	if _, e = r.PrepareControlSnapshot(context.Background(), stale, 6); e != nil {
		t.Fatal(e)
	}
	client.server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.VerifyControlSnapshot(context.Background(), stale); e != nil {
		t.Fatal("candidate after repository reopen", e)
	}
	func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if e = appendControl(r.site, "site_name_update", []store.Mutation{mutation("site", "state", json.RawMessage(r.site.State().Rows["site:state"].Value), nil)}, []string{}); e != nil {
			t.Fatal(e)
		}
	}()
	if _, e = r.VerifyControlSnapshot(context.Background(), stale); e == nil {
		t.Fatal("stale transfer accepted")
	}
	importCandidateAudit(t, r)
	if _, e = r.VerifyControlSnapshot(context.Background(), stale); e == nil {
		t.Fatal("stale source accepted")
	}
}

func TestControlCandidateRefusesUnsafeAndIncomplete(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	parent := candidateParent(t)
	dir := filepath.Join(parent, "unimported")
	if _, e := r.PrepareControlSnapshot(context.Background(), dir, 6); e == nil {
		t.Fatal("unimported audit")
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("output before proof")
	}
	importCandidateAudit(t, r)
	for _, output := range []string{filepath.Join(cfg.DataDir, "candidate"), "relative-candidate"} {
		if _, e := r.PrepareControlSnapshot(context.Background(), output, 6); e == nil {
			t.Fatal("unsafe output", output)
		}
	}
	if _, e := r.PrepareControlSnapshot(context.Background(), filepath.Join(parent, "level"), 5); e == nil {
		t.Fatal("unsupported codec")
	}
	link := filepath.Join(parent, "link")
	if e := os.Symlink(parent, link); e != nil {
		t.Fatal(e)
	}
	if _, e := r.PrepareControlSnapshot(context.Background(), filepath.Join(link, "candidate"), 6); e == nil {
		t.Fatal("symlink parent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.checkpoint = func(point string) {
		if point == "snapshot_candidate_file" {
			cancel()
		}
	}
	partial := filepath.Join(parent, "partial")
	if _, e := r.PrepareControlSnapshot(ctx, partial, 6); e == nil {
		t.Fatal("cancelled candidate")
	}
	if _, e := os.Stat(filepath.Join(partial, "candidate.json")); !os.IsNotExist(e) {
		t.Fatal("completion marker after cancellation")
	}
	if _, e := r.VerifyControlSnapshot(context.Background(), partial); e == nil {
		t.Fatal("incomplete candidate")
	}
	r.checkpoint = func(string) {}
	good := filepath.Join(parent, "good")
	if _, e := r.PrepareControlSnapshot(context.Background(), good, 6); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(good, "unexpected"), []byte("extra"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := r.VerifyControlSnapshot(context.Background(), good); e == nil {
		t.Fatal("unexpected file")
	}
}

func candidateHeaders(etag, csrf string) http.Header {
	return http.Header{"Content-Type": {"application/json"}, "If-Match": {etag}, "X-CSRF-Token": {csrf}, "Idempotency-Key": {"candidate-settings-001"}}
}
