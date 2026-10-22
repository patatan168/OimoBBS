// 30秒の再送索引がpackから満了しても、61分の受理枠を署名記録から復元する。
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func TestRateHistorySurvivesDedupCompaction(t *testing.T) {
	owner, raw, now := postingFixture(t)
	f, _, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	op.Dedup.Mode, op.Dedup.RequestID = "implicit", nil
	op.Dedup.Expires = now + domain.Time(30*time.Second)
	f.Records[0].JSON, _ = json.Marshal(op)
	raw, e = store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	parent := filepath.Join(root, "threads")
	if e = os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	j, e := evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, key, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	open := func() *PostingLog {
		t.Helper()
		p, e := OpenPosting(parent, owner, 1, []*evidence.Journal{j}, j, now)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	p := open()
	if result := p.Post(context.Background(), raw, []byte(`{"fixture":true}`), now); result.Status != store.Durable {
		t.Fatal(result)
	}
	before, e := p.RateHistory()
	if e != nil || len(before) != 1 || before[0].PostNumber != 1 {
		t.Fatal(before, e)
	}
	if _, e = p.Compact(context.Background(), op.Dedup.Expires, 6, true); e != nil {
		t.Fatal(e)
	}
	if record, ok := p.thread.FirstRecord(); !ok || record.Dedup != nil {
		t.Fatal("test did not expire retry entry", record)
	}
	assertHistory := func() {
		t.Helper()
		after, e := p.RateHistory()
		if e != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("quota lost with retry entry", after, e)
		}
	}
	assertHistory()
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	p = open()
	defer p.Close()
	assertHistory()
	entry := p.proposals[f.Records[0].ID]
	entry.payload.Frame = "AA=="
	p.proposals[f.Records[0].ID] = entry
	if _, e = p.RateHistory(); e == nil {
		t.Fatal("corrupt rate evidence silently omitted")
	}
}
