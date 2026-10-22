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
	j := &Journal{preparedPayloads: map[domain.Hash]preparedPayload{hash: {"attempt", raw}}, validate: func(string, []byte) error { calls++; return reject }}
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
