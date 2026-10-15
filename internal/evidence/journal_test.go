// 署名journalの実ファイル再読込と追記専用境界を検査する。
package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"testing"
)

type testPayload struct {
	Owner   domain.ID  `json:"source_owner_id"`
	Day     domain.U64 `json:"source_subkey"`
	Seq     domain.U64 `json:"source_control_seq"`
	Content string     `json:"content"`
}

func testValidator(kind string, b []byte) error { var p testPayload; return strictjson.Decode(b, &p) }
func TestJournalDiskAndChain(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	owner := domain.NewID()
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(parent, "20260928")
	open := func() *Journal {
		t.Helper()
		j, e := OpenJournal(path, owner, 20260928, 10, key, testValidator)
		if e != nil {
			t.Fatal(e)
		}
		return j
	}
	j := open()
	for i := 0; i < 2; i++ {
		_, r := j.Append(domain.NewID(), "attempt", 1, func(s Source) ([]byte, error) {
			return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "private"})
		})
		if r.Status != store.Durable {
			t.Fatal(r)
		}
	}
	entries := j.Entries()
	if len(entries) != 2 || entries[1].Event.PreviousSHA != entries[0].Event.EventSHA {
		t.Fatal("chain")
	}
	if e := j.Close(); e != nil {
		t.Fatal(e)
	}
	j = open()
	defer j.Close()
	if len(j.Entries()) != 2 {
		t.Fatal("replay")
	}
	_, r := j.Append(entries[0].Event.RecordID, "attempt", 1, func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "overwrite"})
	})
	if r.Status != store.NotWritten {
		t.Fatal("ID reuse", r)
	}
	// ID索引に欠落があっても事前検証は保存済みの対象行を照合する。
	delete(j.ids, entries[0].Event.RecordID)
	_, r = j.Append(entries[0].Event.RecordID, "attempt", 1, func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "overwrite"})
	})
	if r.Status != store.NotWritten || len(j.Entries()) != 2 || j.log.State().Seq != 2 {
		t.Fatal("preflight lost existing target", r)
	}
	_, r = j.Append(domain.NewID(), "attempt", 1, func(s Source) ([]byte, error) { return []byte(`{"secret":"raw password"}`), nil })
	if r.Status != store.NotWritten || len(j.Entries()) != 2 {
		t.Fatal("invalid payload written")
	}
}

// CRCと個別署名が正しくても、保存seqと署名source/前hashが違えば開けない。
func TestJournalRejectsIndividuallySignedBrokenChain(t *testing.T) {
	for _, mode := range []string{"previous", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			owner := domain.NewID()
			parent := t.TempDir()
			if e := os.Chmod(parent, 0700); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(parent, "20260928")
			j, e := OpenJournal(path, owner, 20260928, 10, key, testValidator)
			if e != nil {
				t.Fatal(e)
			}
			first, r := j.Append(domain.NewID(), "attempt", 1, func(s Source) ([]byte, error) {
				return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "first"})
			})
			if r.Status != store.Durable {
				t.Fatal(r)
			}
			source := Source{owner, 20260928, 2}
			previous := first.EventSHA
			if mode == "previous" {
				previous = domain.Hash{}
			} else {
				source.Seq = 3
			}
			payload, e := json.Marshal(testPayload{source.Owner, domain.U64(source.Subkey), domain.U64(source.Seq), "second"})
			if e != nil {
				t.Fatal(e)
			}
			forged, e := Seal(source, domain.NewID(), "attempt", payload, previous, 10, key)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := json.Marshal(forged)
			if e != nil {
				t.Fatal(e)
			}
			op := store.ControlOperation{Schema: 1, Seq: 2, ExpectedSeq: 1, Committed: 1, Actor: domain.Actor{Kind: "system", Reason: "test"}, Mutations: []store.Mutation{{Collection: "attempt", Key: forged.RecordID.String(), Value: raw}}, Result: store.ControlResult{Code: "test", Targets: []string{}}}
			b, e := json.Marshal(op)
			if e != nil {
				t.Fatal(e)
			}
			frame, e := store.EncodeFrame(store.Frame{FirstSeq: 2, Records: []store.Record{{ID: forged.RecordID, JSON: b}}})
			if e != nil {
				t.Fatal(e)
			}
			if r = j.log.Append(frame); r.Status != store.Durable {
				t.Fatal("fixture not individually valid", r)
			}
			if e = j.Close(); e != nil {
				t.Fatal(e)
			}
			opened, e := OpenJournal(path, owner, 20260928, 10, key, testValidator)
			if e == nil {
				opened.Close()
				t.Fatal("broken chain accepted")
			}
		})
	}
}
