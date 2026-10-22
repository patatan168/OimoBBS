// 並列デコードでも検証・適用・失敗結果は元のframe順を保ち、先行保存しないことを検査する。
package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"reflect"
	"strings"
	"testing"
)

func TestControlParallelDecodePreservesOrderAndFailure(t *testing.T) {
	frames := make([][]byte, 64)
	for i := range frames {
		seq := domain.U64(i + 1)
		op := ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: seq - 1, Actor: domain.Actor{Kind: "system", Reason: "test"}, Mutations: []Mutation{{Collection: "board", Key: "state", ExpectedRevision: seq - 1, Value: json.RawMessage(fmt.Sprintf(`{"number":%d,"body":"%s"}`, seq, strings.Repeat("a", 1024)))}}, Result: ControlResult{Code: "updated", Targets: []string{}}}
		raw, _ := json.Marshal(op)
		var err error
		frames[i], err = EncodeFrame(Frame{FirstSeq: uint64(seq), Records: []Record{{ID: domain.NewID(), JSON: raw}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, broken := range []int{-1, 0, 31, 63} {
		t.Run(fmt.Sprint(broken), func(t *testing.T) {
			trial := append([][]byte(nil), frames...)
			if broken >= 0 {
				f, _, _ := ReadFrame(bytes.NewReader(trial[broken]))
				f.Records[0].JSON = bytes.Replace(f.Records[0].JSON, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
				trial[broken], _ = EncodeFrame(f)
			}
			calls := 0
			validate := func(_, _ string, old, next json.RawMessage) error {
				calls++
				if calls > 1 && !bytes.Equal(old, expectedControlValue(t, frames[calls-2])) {
					t.Fatal("validator observed reordered predecessor", calls)
				}
				if !bytes.Equal(next, expectedControlValue(t, frames[calls-1])) {
					t.Fatal("validator called out of input order", calls)
				}
				return nil
			}
			writer := &batchSyncWriter{faultWriter: &faultWriter{}}
			log := &ControlLog{header: Header{Kind: 2}, state: ControlState{Rows: map[string]ControlRow{}}, validator: validate, writer: NewWriter(writer)}
			before := log.State()
			result := log.AppendBatch(trial)
			if broken >= 0 {
				if result.Status != NotWritten || calls != 0 || writer.writes != 0 || !reflect.DeepEqual(before, log.State()) {
					t.Fatal("invalid batch reached validation or persistence", result, calls, writer.writes)
				}
			} else if result.Status != Durable || calls != 64 || log.State().Seq != 64 || writer.writes != 1 || writer.syncs != 1 || before.Seq != 0 || len(before.Rows) != 0 {
				t.Fatal("batch boundary changed", result, calls, writer.writes, writer.syncs)
			}
		})
	}
}

func expectedControlValue(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	f, _, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	op, err := decodeControlOperation(f)
	if err != nil {
		t.Fatal(err)
	}
	return op.Mutations[0].Value
}
