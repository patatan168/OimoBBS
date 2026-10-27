// 検査結果の共有範囲が一回の追記・同じ元byteだけで、失敗や再起動へ残らないことを検査する。
package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
)

func TestPreparedPayloadExactMatchOnly(t *testing.T) {
	raw := []byte(`{"a":1}`)
	hash := sha256.Sum256(raw)
	calls := 0
	reject := errors.New("完全検査を実行")
	j := &Journal{preparedPayloads: map[domain.Hash]preparedPayload{hash: {kind: "attempt", raw: raw}}, validate: func(string, []byte) error { calls++; return reject }}
	if err := j.validatePreparedPayload(Event{Kind: "attempt", PayloadSHA: hash}, raw); err != nil || calls != 0 {
		t.Fatal(err, calls)
	}
	for _, v := range []struct {
		kind string
		hash domain.Hash
		raw  []byte
	}{{"response", hash, raw}, {"attempt", hash, []byte(`{"a":2}`)}, {"attempt", domain.Hash{}, raw}} {
		if err := j.validatePreparedPayload(Event{Kind: v.kind, PayloadSHA: v.hash}, v.raw); !errors.Is(err, reject) {
			t.Fatal("異なる入力の検査が省略された", err)
		}
	}
	j.preparedPayloads = nil
	if err := j.validatePreparedPayload(Event{Kind: "attempt", PayloadSHA: hash}, raw); !errors.Is(err, reject) || calls != 4 {
		t.Fatal(err, calls)
	}
}

func TestRequiredBatchPreparedValidationScope(t *testing.T) {
	j, key, owner, path := optionalJournalFixture(t)
	// 合成完全スキーマで呼出し数と再起動の再検査を観測する。
	calls := 0
	validator := func(kind string, raw []byte) error { calls++; return testValidator(kind, raw) }
	j.validate = validator
	build := func(src Source) ([]byte, error) {
		return json.Marshal(testPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), "private"})
	}
	if _, r := j.Append(domain.NewID(), "attempt", 1, build); r.Status != store.Durable {
		t.Fatal(r)
	}
	calls = 0
	requests := []AppendRequest{{domain.NewID(), "attempt", 1, build}, {domain.NewID(), "attempt", 1, build}}
	if _, r := j.AppendBatch(requests); r.Status != store.Durable || calls != len(requests) || j.preparedPayloads != nil {
		t.Fatal(r, calls)
	}
	before := j.CommitStats()
	requests[1].Build = func(Source) ([]byte, error) { return nil, errors.New("invalid") }
	if _, r := j.AppendBatch(requests); r.Status != store.NotWritten || j.CommitStats() != before || j.preparedPayloads != nil {
		t.Fatal(r)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	calls = 0
	reopened, err := OpenJournal(path, owner, 20261005, 10, key, validator)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if calls < 3 || reopened.preparedPayloads != nil || len(reopened.Entries()) != 3 {
		t.Fatal("再起動の完全検査が行われなかった", calls)
	}
}

// TestPreparedPayloadSourceBinding は私的元byteの再利用でも元source・署名・base64の改変を拒否する。
func TestPreparedPayloadSourceBinding(t *testing.T) {
	j, key, owner, _ := optionalJournalFixture(t)
	j.validate = testValidator
	defer j.Close()
	src := Source{owner, j.day, 1}
	raw, err := json.Marshal(testPayload{owner, domain.U64(j.day), 1, "private"})
	if err != nil {
		t.Fatal(err)
	}
	event, err := Seal(src, domain.NewID(), "attempt", raw, domain.Hash{}, j.keyID, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.validatePayload(event.Kind, raw); err != nil {
		t.Fatal(err)
	}
	j.preparedPayloads = map[domain.Hash]preparedPayload{event.PayloadSHA: {kind: "attempt", raw: raw, source: src}}
	check := func(event Event, want bool) {
		t.Helper()
		encoded, e := json.Marshal(event)
		if e != nil {
			t.Fatal(e)
		}
		err := j.validateValue(event.Kind, event.RecordID.String(), nil, encoded)
		if (err == nil) != want {
			t.Fatalf("accepted=%v want=%v: %v", err == nil, want, err)
		}
	}
	check(event, true)
	for _, mutate := range []func(*Event){
		func(e *Event) { e.Payload += "\n" }, func(e *Event) { e.Payload = "e30=" }, func(e *Event) { e.Signature = "AAAA" }, func(e *Event) { e.PayloadSHA[0] ^= 1 }, func(e *Event) { e.RecordID[0] ^= 1 }, func(e *Event) { e.Kind = "response" },
	} {
		changed := event
		mutate(&changed)
		check(changed, false)
	}
	changed := src
	changed.Seq++
	j.preparedPayloads[event.PayloadSHA] = preparedPayload{kind: "attempt", raw: raw, source: changed}
	check(event, false)
	j.preparedPayloads = nil
	check(event, true)
}
