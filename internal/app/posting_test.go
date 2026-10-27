// 実ファイル上の投稿・evidence確定順と、停止後の再送を検査する。
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"testing"
)

func postingFixture(t *testing.T) (domain.ID, []byte, domain.Time) {
	t.Helper()
	b, e := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Board     domain.ID       `json:"board_id_hex"`
		ID        domain.ID       `json:"operation_id_hex"`
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	dat, e := hex.DecodeString(f.DAT)
	if e != nil {
		t.Fatal(e)
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: 1, Records: []store.Record{{ID: f.ID, JSON: f.Operation, DAT: dat}}})
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Operation)
	if e != nil {
		t.Fatal(e)
	}
	return f.Board, frame, op.Committed
}
func fixtureCapture(b []byte) error {
	var c struct {
		Fixture bool `json:"fixture"`
	}
	return strictjson.Decode(b, &c)
}

func TestPostingDurabilityAndRetry(t *testing.T) {
	for _, stop := range []string{"", "proposal", "thread", "decision"} {
		t.Run(stop, func(t *testing.T) {
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
			open := func() (*PostingLog, *evidence.Journal) {
				t.Helper()
				j, e := evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, key, PostingValidator(fixtureCapture))
				if e != nil {
					t.Fatal(e)
				}
				p, e := OpenPosting(threads, owner, 1700000000, []*evidence.Journal{j}, j, now)
				if e != nil {
					t.Fatal(e)
				}
				return p, j
			}
			p, j := open()
			if stop != "" {
				p.checkpoint = func(stage string) error {
					if stage == stop {
						return errors.New("simulated stop")
					}
					return nil
				}
			}
			reader := p.PublicReader()
			got := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now)
			public, status := reader.Snapshot(now)
			if stop == "" && (status != 200 || public == nil) || stop != "" && (status != 503 || public != nil) {
				t.Fatal("parallel reader exposed unconfirmed post", stop, status)
			}
			if stop == "" && got.Status != store.Durable || stop != "" && got.Status != store.Unknown {
				t.Fatal(got)
			}
			if stop != "" && p.Snapshot(now) != nil {
				t.Fatal("published before all Syncs")
			}
			_ = p.Close()
			_ = j.Close()
			p, j = open()
			defer p.Close()
			defer j.Close()
			if stop == "proposal" {
				if p.Snapshot(now) != nil {
					t.Fatal("proposal resurrected")
				}
				if got := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); got.Status != store.NotWritten {
					t.Fatal("reused operation ID", got)
				}
				return
			}
			if p.Snapshot(now) == nil || p.Snapshot(now).PostCount != 1 {
				t.Fatal("missing recovered post")
			}
			before := len(j.Entries())
			got = p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now)
			if got.Status != store.Durable || !got.Duplicate || len(j.Entries()) != before {
				t.Fatal("retry wrote twice", got)
			}
		})
	}
}

// 再送HMACはHTTP入力正規化層の責務。本試験では異なる要求の値を明示して与える。
func replyFixture(t *testing.T, create []byte) []byte {
	t.Helper()
	f, op, e := postingFrame(create)
	if e != nil {
		t.Fatal(e)
	}
	var c domain.Create
	if e = json.Unmarshal(op.Payload, &c); e != nil {
		t.Fatal(e)
	}
	post := c.Posts[0]
	post.Number = 2
	op.Type = "append"
	op.Revision = 2
	op.Versions.Thread = 1
	op.After.PostCount = 2
	op.After.UserCount = 2
	op.After.DATBytes *= 2
	op.Dedup.PostNumber = 2
	op.Dedup.Request[0] ^= 1
	(*op.Dedup.RequestID)[0] ^= 1
	op.Payload, e = json.Marshal(domain.Append{Posts: []domain.Post{post}})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(op)
	if e != nil {
		t.Fatal(e)
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: 2, Records: []store.Record{{ID: domain.NewID(), JSON: raw, DAT: f.Records[0].DAT}}})
	if e != nil {
		t.Fatal(e)
	}
	return frame
}
func newPostingTest(t *testing.T) (*PostingLog, *evidence.Journal, []byte, domain.Time, string, ed25519.PrivateKey) {
	t.Helper()
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
	p, e := OpenPosting(threads, owner, 1700000000, []*evidence.Journal{j}, j, now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = p.Close(); _ = j.Close() })
	return p, j, frame, now, root, key
}
func TestPostingReplyRecoveryAndConflict(t *testing.T) {
	p, j, frame, now, _, _ := newPostingTest(t)
	capture := []byte(`{"fixture":true}`)
	if r := p.Post(context.Background(), frame, capture, now); r.Status != store.Durable {
		t.Fatal(r)
	}
	reply := replyFixture(t, frame)
	p.checkpoint = func(stage string) error {
		if stage == "thread" {
			return errors.New("stop")
		}
		return nil
	}
	if r := p.Post(context.Background(), reply, capture, now); r.Status != store.Unknown {
		t.Fatal(r)
	}
	if p.Snapshot(now).PostCount != 1 {
		t.Fatal("unconfirmed reply published")
	}
	_ = p.Close()
	p, e := OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, now)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if p.Snapshot(now).PostCount != 2 {
		t.Fatal("reply not recovered")
	}
	before := len(j.Entries())
	if r := p.Post(context.Background(), reply, capture, now); !r.Duplicate || r.PostNumber != 2 {
		t.Fatal(r)
	}
	f, op, e := postingFrame(reply)
	if e != nil {
		t.Fatal(e)
	}
	op.Dedup.Request[0] ^= 1
	f.Records[0].JSON, _ = json.Marshal(op)
	conflict, _ := store.EncodeFrame(f)
	if r := p.Post(context.Background(), conflict, capture, now); r.Status != store.NotWritten || r.Err == nil {
		t.Fatal("conflict accepted", r)
	}
	if len(j.Entries()) != before {
		t.Fatal("retry/conflict changed journal")
	}
	shared := p.SharedSnapshot(now)
	original := bytes.Clone(shared.DAT)
	p.publish()
	if !bytes.Equal(shared.DAT, original) {
		t.Fatal("publish mutated shared snapshot")
	}
	if &p.SharedSnapshot(now).DAT[0] != &p.snapshot.DAT[0] {
		t.Fatal("shared snapshot copied DAT")
	}
	snap := p.Snapshot(now)
	if bytes.Contains(snap.DAT, []byte("192.0.2.1")) {
		t.Fatal("private IP in snapshot")
	}
	snap.DAT[0] ^= 1
	if bytes.Equal(snap.DAT, p.Snapshot(now).DAT) {
		t.Fatal("snapshot aliases published state")
	}
	if p.Snapshot(snap.Expires) != nil || p.Snapshot(now) != nil || p.SharedSnapshot(now) != nil {
		t.Fatal("expired snapshot exposed")
	}
	if r := p.Post(context.Background(), reply, capture, snap.Expires); r.Status != store.NotWritten {
		t.Fatal("expired retry succeeded")
	}
}
func TestPostingEvidenceGap(t *testing.T) {
	for _, missing := range []string{"proposal", "thread", "current", "crc"} {
		t.Run(missing, func(t *testing.T) {
			p, j, frame, now, root, key := newPostingTest(t)
			if r := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); r.Status != store.Durable {
				t.Fatal(r)
			}
			_ = p.Close()
			switch missing {
			case "proposal":
				_ = j.Close()
				if e := os.RemoveAll(filepath.Join(root, "20231114")); e != nil {
					t.Fatal(e)
				}
				var e error
				j, e = evidence.OpenJournal(filepath.Join(root, "20231114"), p.owner, 20231114, 10, key, PostingValidator(fixtureCapture))
				if e != nil {
					t.Fatal(e)
				}
				defer j.Close()
			case "thread":
				if e := os.RemoveAll(filepath.Join(p.parent, "1700000000")); e != nil {
					t.Fatal(e)
				}
			case "current":
				if e := os.Remove(filepath.Join(p.parent, "1700000000", "current.json")); e != nil {
					t.Fatal(e)
				}
			case "crc":
				path := filepath.Join(p.parent, "1700000000", "delta-000001.wal")
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				b[len(b)-1] ^= 1
				if e = os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := len(j.Entries())
			opened, e := OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, now)
			if e == nil {
				opened.Close()
				t.Fatal("gap accepted")
			}
			if !errors.Is(e, ErrEvidenceGap) || len(j.Entries()) != before {
				t.Fatalf("gap not isolated: %v", e)
			}
		})
	}
}
func TestPostingRejectsBeforeWriting(t *testing.T) {
	p, j, frame, now, _, _ := newPostingTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := p.Post(ctx, frame, []byte(`{"fixture":true}`), now); r.Status != store.NotWritten {
		t.Fatal(r)
	}
	if r := p.Post(context.Background(), frame, []byte(`{"password":"do-not-store"}`), now); r.Status != store.NotWritten {
		t.Fatal(r)
	}
	if len(j.Entries()) != 0 || p.Snapshot(now) != nil {
		t.Fatal("rejected input saved")
	}
	if _, e := os.Stat(filepath.Join(p.parent, "1700000000")); !os.IsNotExist(e) {
		t.Fatal("thread created before proposal validation")
	}
}

func TestPostingPartialReplyIsNotAccepted(t *testing.T) {
	p, j, frame, now, _, _ := newPostingTest(t)
	if r := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); r.Status != store.Durable {
		t.Fatal(r)
	}
	reply := replyFixture(t, frame)
	p.checkpoint = func(stage string) error {
		if stage == "proposal" {
			return errors.New("stop")
		}
		return nil
	}
	if r := p.Post(context.Background(), reply, []byte(`{"fixture":true}`), now); r.Status != store.Unknown {
		t.Fatal(r)
	}
	_ = p.Close()
	wal := filepath.Join(p.parent, "1700000000", "delta-000001.wal")
	f, e := os.OpenFile(wal, os.O_APPEND|os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(reply[:len(reply)/2]); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	p, e = OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, now)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if p.Snapshot(now).PostCount != 1 {
		t.Fatal("partial reply exposed")
	}
	var d postingDecision
	entries := j.Entries()
	if e = json.Unmarshal(entries[len(entries)-1].Payload, &d); e != nil || d.Outcome != "not_accepted" {
		t.Fatalf("wrong recovery decision: %+v %v", d, e)
	}
	block, e := store.EncodeWALBlock([][]byte{frame})
	if e != nil {
		t.Fatal(e)
	}
	stat, e := os.Stat(wal)
	if e != nil || stat.Size() != int64(store.HeaderSize+len(block)) {
		t.Fatal("partial tail not removed", e)
	}
}

func TestPostingRecoveryAcrossDaysKeepsOriginalExpiry(t *testing.T) {
	p, first, frame, now, root, key := newPostingTest(t)
	p.checkpoint = func(stage string) error {
		if stage == "thread" {
			return errors.New("stop")
		}
		return nil
	}
	if r := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); r.Status != store.Unknown {
		t.Fatal(r)
	}
	_ = p.Close()
	next, e := evidence.OpenJournal(filepath.Join(root, "20240514"), p.owner, 20240514, 10, key, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	original := postRetention(now)
	p, e = OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{next, first}, next, original)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if p.Snapshot(original) != nil || p.Snapshot(now) != nil {
		t.Fatal("expired thread resurrected")
	}
	entries := next.Entries()
	if len(entries) != 1 {
		t.Fatal("decision missing")
	}
	var d postingDecision
	if e = json.Unmarshal(entries[0].Payload, &d); e != nil {
		t.Fatal(e)
	}
	if d.Committed != now || d.Retention != original || !d.Recovered || d.Outcome != "accepted" {
		t.Fatalf("original retention changed: %+v", d)
	}
}

func TestPostingImplicitRetryAndStartedCancellation(t *testing.T) {
	p, j, frame, now, _, _ := newPostingTest(t)
	f, op, e := postingFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	op.Dedup.Mode = "implicit"
	op.Dedup.RequestID = nil
	op.Dedup.Expires = now + 30*1e9
	f.Records[0].JSON, e = json.Marshal(op)
	if e != nil {
		t.Fatal(e)
	}
	frame, e = store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.checkpoint = func(stage string) error {
		if stage == "proposal" {
			cancel()
		}
		return nil
	}
	if r := p.Post(ctx, frame, []byte(`{"fixture":true}`), now); r.Status != store.Durable {
		t.Fatal("started post cancelled", r)
	}
	if ctx.Err() == nil {
		t.Fatal("test did not cancel context")
	}
	_ = p.Close()
	p, e = OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, now)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if r := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now+29*1e9); !r.Duplicate || r.Status != store.Durable {
		t.Fatal(r)
	}
	if r := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now+30*1e9); r.Status != store.NotWritten {
		t.Fatal("expired retry result returned", r)
	}
	if len(j.Entries()) != 2 {
		t.Fatal("retry added evidence")
	}
}
