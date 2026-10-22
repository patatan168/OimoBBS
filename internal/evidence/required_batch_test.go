// 必須journalの一括同期数、事前全件検証、署名連鎖の再起動照合を検査する。
package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestRequiredBatchDiskAndValidation(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	owner := domain.NewID()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "20260928")
	open := func() *Journal {
		t.Helper()
		j, e := OpenJournal(path, owner, 20260928, 10, key, testValidator)
		if e != nil {
			t.Fatal(e)
		}
		return j
	}
	j := open()
	build := func(src Source) ([]byte, error) {
		return json.Marshal(testPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), "private"})
	}
	if _, r := j.Append(domain.NewID(), "attempt", 1, build); r.Status != store.Durable {
		t.Fatal(r)
	}
	before := j.CommitStats()
	requests := []AppendRequest{{domain.NewID(), "attempt", 1, build}, {domain.NewID(), "attempt", 1, build}, {domain.NewID(), "attempt", 1, build}}
	invalid := append([]AppendRequest(nil), requests...)
	invalid[2].Build = func(Source) ([]byte, error) { return nil, errors.New("invalid last payload") }
	if _, r := j.AppendBatch(invalid); r.Status != store.NotWritten || j.CommitStats() != before || len(j.Entries()) != 1 {
		t.Fatal("invalid later item started storage", r)
	}
	events, r := j.AppendBatch(requests)
	after := j.CommitStats()
	if r.Status != store.Durable || len(events) != 3 || after.Syncs-before.Syncs != 1 || after.Writes-before.Writes != 1 {
		t.Fatal(r, events, after)
	}
	if e := j.Close(); e != nil {
		t.Fatal(e)
	}
	j = open()
	defer j.Close()
	if len(j.Entries()) != 4 {
		t.Fatal(len(j.Entries()))
	}
	for i, entry := range j.Entries() {
		if i > 0 && entry.Event.PreviousSHA != j.Entries()[i-1].Event.EventSHA {
			t.Fatal("broken chain")
		}
	}
	before = j.CommitStats()
	if _, r := j.AppendBatch(requests); r.Status != store.NotWritten || j.CommitStats() != before {
		t.Fatal("duplicate stored", r)
	}
}
