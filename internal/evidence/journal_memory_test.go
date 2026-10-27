// 非必須ログの重複base64を保持しなくても、元byte・署名・照会・再起動が一致することを検査する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestOptionalJournalCompactMemoryKeepsSignedBytes(t *testing.T) {
	j, key, owner, path := optionalJournalFixture(t)
	original := appendOptionalFixture(t, j, 100, "EXACT_SYNTHETIC_USER_AGENT")
	want, _ := json.Marshal(original)
	check := func(j *Journal) {
		t.Helper()
		if !j.HasKind(j.entries[0].Event.Kind) || j.HasKind("missing_kind") {
			t.Fatal("検証済み種別の存在確認が変化した")
		}
		if len(j.entries) != 1 || j.entries[0].Event.Payload != "" || len(j.entries[0].Payload) == 0 {
			t.Fatal("同じpayloadのbase64と元byteを二重保持した")
		}
		entries := j.Entries()
		entry, found, err := j.Lookup(original.RecordID)
		if err != nil || !found {
			t.Fatal(found, err)
		}
		seen := 0
		if err = j.Visit(func(e Entry) error { entries = append(entries, e); seen++; return nil }); err != nil || seen != 1 {
			t.Fatal(seen, err)
		}
		entries = append(entries, entry)
		for _, entry := range entries {
			actual, _ := json.Marshal(entry.Event)
			if !bytes.Equal(actual, want) {
				t.Fatal("署名envelopeの元byteが変化した")
			}
			payload, err := Verify(Source{owner, 20261005, 1}, entry.Event, domain.Hash{}, 10, key.Public().(ed25519.PublicKey))
			if err != nil || !bytes.Equal(payload, entry.Payload) {
				t.Fatal("元payload/署名の不一致", err)
			}
		}
	}
	check(j)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(path, owner, 20261005, 10, key, ValidateOptionalPayload)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	check(reopened)
}

func TestRequiredJournalCompactMemoryKeepsSignedBytes(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	owner := domain.NewID()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "20260928")
	open := func() *Journal {
		t.Helper()
		j, err := OpenJournal(path, owner, 20260928, 10, key, testValidator)
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	j := open()
	build := func(src Source) ([]byte, error) {
		raw, err := json.Marshal(testPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), "元byteを保持する合成原本"})
		// 正当な空白を含む元表現も、JSON再符号化で変えてはならない。
		return append(append([]byte(" \n "), raw...), '\t', ' '), err
	}
	first, result := j.Append(domain.NewID(), "evidence_proposal", 1, build)
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	events, result := j.AppendBatch([]AppendRequest{{domain.NewID(), "evidence_decision", 1, build}, {domain.NewID(), "rejected_connection", 1, build}})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	want := append([]Event{first}, events...)
	check := func(j *Journal) {
		t.Helper()
		if !j.HasKind(j.entries[0].Event.Kind) || j.HasKind("missing_kind") {
			t.Fatal("検証済み種別の存在確認が変化した")
		}
		for _, entry := range j.entries {
			if entry.Payload != nil || entry.Event.Payload == "" {
				t.Fatal("必須原本を二重保持した")
			}
		}
		entries := j.Entries()
		if err := j.Visit(func(entry Entry) error { entries = append(entries, entry); return nil }); err != nil {
			t.Fatal(err)
		}
		for _, event := range want {
			entry, found, err := j.Lookup(event.RecordID)
			if err != nil || !found {
				t.Fatal(found, err)
			}
			entries = append(entries, entry)
		}
		for index, entry := range entries {
			original := want[index%len(want)]
			if entry.Event != original {
				t.Fatal("署名envelopeが変化した")
			}
			payload, err := Verify(Source{owner, 20260928, uint64(index%len(want) + 1)}, entry.Event, original.PreviousSHA, 10, key.Public().(ed25519.PublicKey))
			if err != nil || !bytes.Equal(payload, entry.Payload) {
				t.Fatal("元payload/署名の不一致", err)
			}
		}
		entries[0].Payload[0] ^= 1
		if !json.Valid(j.Entries()[0].Payload) {
			t.Fatal("照会結果の変更が保存参照へ波及した")
		}
	}
	check(j)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = open()
	defer j.Close()
	check(j)
}
