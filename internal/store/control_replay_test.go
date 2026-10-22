// 復旧候補の有界性、複数mutationの原子性と通常ApplyControlとの一致を検査する。
package store

import (
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"reflect"
	"strings"
	"testing"
)

func controlReplayFixture(t *testing.T) (ControlState, ControlOperation) {
	t.Helper()
	rows := make(map[string]ControlRow, 10000)
	for n := 0; n < 10000; n++ {
		rows[fmt.Sprintf("transfer:k%d", n)] = ControlRow{Revision: 1, Value: json.RawMessage(`{"v":1}`)}
	}
	return ControlState{Seq: 9, Rows: rows}, ControlOperation{Schema: 1, Seq: 10, ExpectedSeq: 9, Committed: 1, Actor: domain.Actor{Kind: "system", Reason: "replay"}, Mutations: []Mutation{{Collection: "transfer", Key: "k1", ExpectedRevision: 1, Value: json.RawMessage(`{"v":2}`)}, {Collection: "transfer", Key: "k2", ExpectedRevision: 1, Value: json.RawMessage(`null`)}}, Result: ControlResult{Code: "replayed", Targets: []string{}}}
}

func controlReplayFrame(t *testing.T, op ControlOperation) Frame {
	t.Helper()
	raw, e := json.Marshal(op)
	if e != nil {
		t.Fatal(e)
	}
	return Frame{FirstSeq: uint64(op.Seq), Records: []Record{{ID: domain.NewID(), JSON: raw}}}
}

func TestControlReplayMatchesImmutableApplyWithBoundedCandidate(t *testing.T) {
	old, op := controlReplayFixture(t)
	expiry := domain.Time(20)
	op.Mutations[0].Expires = &expiry
	subset := controlReplaySubset(old, op.Mutations)
	if len(subset.Rows) != 2 {
		t.Fatal("copied unrelated rows", len(subset.Rows))
	}
	frame := controlReplayFrame(t, op)
	validator := func(_, _ string, _, next json.RawMessage) error { return validateControlReplayValue(next) }
	expected, e := ApplyControl(old, 9, frame, validator)
	if e != nil {
		t.Fatal(e)
	}
	if len(old.Rows) != 10000 || old.Seq != 9 {
		t.Fatal("immutable apply changed prior state")
	}
	got, e := applyControlReplay(old, 9, frame, validator)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(got, expected) || len(got.Rows) != 9999 {
		t.Fatal("replay differs from candidate apply")
	}
	if got.Rows["transfer:k1"].Expires == &expiry {
		t.Fatal("retained mutation expiry pointer")
	}
}

func TestControlReplayRejectsBeforeAnyMutation(t *testing.T) {
	for _, kind := range []string{"revision", "duplicate", "validator", "result", "sequence"} {
		t.Run(kind, func(t *testing.T) {
			old, op := controlReplayFixture(t)
			baseline, e := json.Marshal(old)
			if e != nil {
				t.Fatal(e)
			}
			damageControlReplayOperation(&op, kind)
			validator := func(_, key string, _, next json.RawMessage) error {
				if kind == "validator" && key == "k2" {
					return ErrCorrupt
				}
				return validateControlReplayValue(next)
			}
			next, e := applyControlReplay(old, 9, controlReplayFrame(t, op), validator)
			if e == nil {
				t.Fatal("invalid replay accepted", kind)
			}
			actual, e := json.Marshal(next)
			if e != nil || string(actual) != string(baseline) {
				t.Fatal("failed replay changed prior state", e)
			}
		})
	}
}

func damageControlReplayOperation(op *ControlOperation, kind string) {
	switch kind {
	case "revision":
		op.Mutations[1].ExpectedRevision++
	case "duplicate":
		op.Mutations[1] = op.Mutations[0]
	case "result":
		op.Result.Code = "INVALID"
	case "sequence":
		op.ExpectedSeq--
	}
}

// validateControlReplayValue は試験の削除nullと完全なobjectを許す。
func validateControlReplayValue(next json.RawMessage) error {
	if string(next) == "null" {
		return nil
	}
	return strictjson.Validate(next)
}

// BenchmarkControlReplay は64件の復旧候補を専有状態へ順に反映するCPU・割り当てを測る。
func BenchmarkControlReplay(b *testing.B) {
	frames := make([]Frame, 64)
	for i := range frames {
		seq := domain.U64(i + 1)
		op := ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: seq - 1, Actor: domain.Actor{Kind: "system", Reason: "benchmark"}, Mutations: []Mutation{{Collection: "board", Key: fmt.Sprint("row", i), Value: json.RawMessage(`{"body":"` + strings.Repeat("x", 4096) + `"}`)}}, Result: ControlResult{Code: "saved", Targets: []string{}}}
		raw, e := json.Marshal(op)
		if e != nil {
			b.Fatal(e)
		}
		frames[i] = Frame{FirstSeq: uint64(seq), Records: []Record{{ID: domain.ID{1}, JSON: raw}}}
	}
	validate := func(_, _ string, _, _ json.RawMessage) error { return nil }
	b.ReportAllocs()
	for b.Loop() {
		state := ControlState{Rows: map[string]ControlRow{}}
		for _, frame := range frames {
			var e error
			state, e = applyControlReplay(state, 2, frame, validate)
			if e != nil {
				b.Fatal(e)
			}
		}
	}
}
