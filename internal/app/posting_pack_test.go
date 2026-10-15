// packの保持下限で回収した再送情報を、時計逆行・再起動で復活させないことを検証する。
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestPostingPackDedupRetention(t *testing.T) {
	owner, frame, now := postingFixture(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	threads := filepath.Join(root, "threads")
	if e := os.Mkdir(threads, 0700); e != nil {
		t.Fatal(e)
	}
	j, e := evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, key, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	p, e := OpenPosting(threads, owner, 1, []*evidence.Journal{j}, j, now)
	if e != nil {
		t.Fatal(e)
	}
	if result := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); result.Status != store.Durable {
		t.Fatal(result)
	}
	record, ok := p.thread.FirstRecord()
	if !ok || record.Dedup == nil {
		t.Fatal("no dedup")
	}
	expiredAt := record.Dedup.Expires
	if _, e = p.Compact(context.Background(), expiredAt, 6, true); e != nil {
		t.Fatal(e)
	}
	if _, ok = p.CreateRetry(record.Dedup, now); ok {
		t.Fatal("clock rollback revived dedup")
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	p, e = OpenPosting(threads, owner, 1, []*evidence.Journal{j}, j, now)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if _, ok = p.CreateRetry(record.Dedup, now); ok {
		t.Fatal("restart revived dedup")
	}
	// 再圧縮でも基準時刻を巻き戻さず、監査満了境界の前後を保持する。
	report, e := p.Compact(context.Background(), now, 9, true)
	if e != nil || report.Generation != 3 {
		t.Fatal(report, e)
	}
	if _, e = p.Compact(context.Background(), now+180*24*60*60*1e9, 6, true); e != nil {
		t.Fatal(e)
	}
	if s := p.Snapshot(now); s == nil {
		t.Fatal("snapshot lost")
	}
}
