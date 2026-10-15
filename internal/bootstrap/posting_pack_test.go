// HTTP投稿からpack切替・再起動・再送・追記・再圧縮までを実ファイルで検証する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestPostingPackRepositoryRoundTrip(t *testing.T) {
	cfg, r := adminFixture(t)
	ctx := context.Background()
	defer func() { _ = r.Close() }()
	info, e := r.CreateBoard(ctx, "pack", "圧縮試験")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	fields := url.Values{"bbs": {"pack"}, "subject": {"pack title"}, "MESSAGE": {"first body"}, "oimo_request_id": {"pack-create-0001"}}
	created, e := sendForm(server, fields)
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	before, e := r.Thread(ctx, info.ID, created.Key)
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(cfg.DataDir, "boards", info.ID.String(), "threads", fmt.Sprint(created.Key))
	old, e := os.ReadFile(filepath.Join(dir, "delta-000001.wal"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.CompactThread(ctx, info.ID, created.Key, 6, true); e == nil {
		t.Fatal("missing version gate")
	}
	report, e := r.CompactThread(ctx, info.ID, created.Key, 6, false)
	if e != nil || report.Applied || report.Generation != 2 {
		t.Fatal(report, e)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 2 {
		t.Fatal("preview wrote files")
	}
	enabled, e := r.EnablePostingPacks(ctx)
	if e != nil || enabled.MinimumReader != 68 || !enabled.AuditComplete {
		t.Fatal(enabled, e)
	}
	report, e = r.CompactThread(ctx, info.ID, created.Key, 6, true)
	if e != nil || !report.Applied {
		t.Fatal(report, e)
	}
	after, e := r.Thread(ctx, info.ID, created.Key)
	if e != nil || !samePublicSnapshot(before, after) {
		t.Fatal("public snapshot changed", e)
	}
	saved, _ := os.ReadFile(filepath.Join(dir, "delta-000001.wal"))
	if sha256.Sum256(old) != sha256.Sum256(saved) {
		t.Fatal("old WAL changed")
	}
	server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	// 非参照旧WALを外した試験保存先でも、署名記録とpackから復旧できる。
	if e = os.Rename(filepath.Join(dir, "delta-000001.wal"), filepath.Join(t.TempDir(), "old.wal")); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	after, e = r.Thread(ctx, info.ID, created.Key)
	if e != nil || !samePublicSnapshot(before, after) {
		t.Fatal("restart changed snapshot", e)
	}
	server = formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	retry, e := sendForm(server, fields)
	if e != nil || !retry.Duplicate || retry.Key != created.Key {
		t.Fatal("create retry", retry, e)
	}
	reply := url.Values{"bbs": {"pack"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"second body"}, "oimo_request_id": {"pack-reply-00001"}}
	posted, e := sendForm(server, reply)
	if e != nil || !posted.Accepted || posted.Number != 2 {
		t.Fatal(posted, e)
	}
	report, e = r.CompactThread(ctx, info.ID, created.Key, 9, true)
	if e != nil || report.Generation != 3 || report.Sequence != 2 {
		t.Fatal(report, e)
	}
	reclaimed, e := r.ReclaimThreadPack(ctx, info.ID, created.Key, false)
	if e != nil || reclaimed.Applied || reclaimed.Files != 2 {
		t.Fatal(reclaimed, e)
	}
	reclaimed, e = r.ReclaimThreadPack(ctx, info.ID, created.Key, true)
	if e != nil || !reclaimed.Applied || reclaimed.Files != 2 {
		t.Fatal(reclaimed, e)
	}
	reclaimed, e = r.ReclaimThreadPack(ctx, info.ID, created.Key, true)
	if e != nil || reclaimed.Files != 0 {
		t.Fatal(reclaimed, e)
	}
	before, e = r.Thread(ctx, info.ID, created.Key)
	if e != nil {
		t.Fatal(e)
	}
	server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	after, e = r.Thread(ctx, info.ID, created.Key)
	if e != nil || !samePublicSnapshot(before, after) {
		t.Fatal("repeated pack recovery", e)
	}
	server = formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	retry, e = sendForm(server, reply)
	if e != nil || !retry.Duplicate || retry.Number != 2 {
		t.Fatal(retry, e)
	}
	if _, e = store.OpenThread(filepath.Dir(dir), info.ID, created.Key); e == nil {
		t.Fatal("unverified pack opened")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = r.CompactThread(canceled, info.ID, created.Key, 6, true); e == nil {
		t.Fatal("canceled compaction")
	}
}

func TestPostingPackRejectsResealedChanges(t *testing.T) {
	cfg, r := adminFixture(t)
	ctx := context.Background()
	board, e := r.CreateBoard(ctx, "pack", "証拠照合")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), board.ID)
	created, e := sendForm(server, url.Values{"bbs": {"pack"}, "subject": {"title"}, "MESSAGE": {"body"}, "oimo_request_id": {"pack-tamper-0001"}})
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	server.Close()
	if _, e = r.EnablePostingPacks(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = r.CompactThread(ctx, board.ID, created.Key, 6, true); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(cfg.DataDir, "boards", board.ID.String(), "threads", fmt.Sprint(created.Key))
	current, e := os.ReadFile(filepath.Join(dir, "current.json"))
	if e != nil {
		t.Fatal(e)
	}
	manifest, e := store.DecodeCurrent(current)
	if e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(filepath.Join(dir, manifest.Base.File))
	if e != nil {
		t.Fatal(e)
	}
	changes := map[string]func(*store.PackSnapshot){
		"private source": func(s *store.PackSnapshot) { s.State.Posts[0].Private.SourceIP = "192.0.2.44" },
		"body":           func(s *store.PackSnapshot) { s.State.Posts[0].Body = "changed" },
		"missing dedup":  func(s *store.PackSnapshot) { s.Dedup = nil },
		"missing audit":  func(s *store.PackSnapshot) { s.Audit = nil },
		"audit reason":   func(s *store.PackSnapshot) { s.Audit[0].Actor.Reason = "other" },
		"last operation": func(s *store.PackSnapshot) { s.LastOperation++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s, e := store.DecodePack(original)
			if e != nil {
				t.Fatal(e)
			}
			change(&s)
			raw, e := store.EncodePack(s, 6)
			if e != nil {
				t.Fatal(e)
			}
			m, e := store.DecodeCurrent(current)
			if e != nil {
				t.Fatal(e)
			}
			m.Base.SHA = sha256.Sum256(raw)
			m.Base.Length = domain.U64(len(raw))
			sealed, e := store.EncodeCurrent(m)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, m.Base.File), raw, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, "current.json"), sealed, 0600); e != nil {
				t.Fatal(e)
			}
			opened, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e == nil {
				_ = opened.Close()
				t.Fatal("changed base accepted")
			}
		})
	}
	if e = os.WriteFile(filepath.Join(dir, manifest.Base.File), original, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "current.json"), current, 0600); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	_ = r.Close()
}

// samePublicSnapshot は送信リースの実行状態を除き、公開DTOの全項目を比較する。
func samePublicSnapshot(a, b *app.PostingSnapshot) bool {
	left, e1 := json.Marshal(a)
	right, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(left, right)
}
