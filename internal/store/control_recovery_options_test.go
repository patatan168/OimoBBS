// 並行復旧でも更新・削除・同一キーは順序適用し、不正seq/CAS/値を公開しないことを検査する。
package store

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"reflect"
	"testing"
)

func TestIndependentReplayMatchesOrderedMutations(t *testing.T) {
	validate := func(_, _ string, old, next json.RawMessage) error {
		if string(next) == `{"bad":true}` {
			return errors.New("bad value")
		}
		return nil
	}
	for _, mode := range []string{"new", "same_key", "update", "delete", "bad_seq", "bad_cas", "bad_value"} {
		t.Run(mode, func(t *testing.T) {
			old := ControlState{Seq: 1, Rows: map[string]ControlRow{"attempt:existing": {Revision: 1, Value: json.RawMessage(`{"v":1}`)}}}
			makeOp := func(seq domain.U64, key string, revision domain.U64, value string) ControlOperation {
				return ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: seq - 1, Committed: 1, Actor: domain.Actor{Kind: "system", Reason: "evidence"}, Mutations: []Mutation{{Collection: "attempt", Key: key, ExpectedRevision: revision, Value: json.RawMessage(value)}}, Result: ControlResult{Code: "evidence_saved", Targets: []string{key}}}
			}
			ops := []ControlOperation{makeOp(2, "first", 0, `{"v":2}`), makeOp(3, "second", 0, `{"v":3}`)}
			switch mode {
			case "same_key":
				ops[1] = makeOp(3, "first", 2, `{"v":3}`)
			case "update":
				ops[0] = makeOp(2, "existing", 1, `{"v":2}`)
			case "delete":
				ops[0] = makeOp(2, "existing", 1, `null`)
			case "bad_seq":
				ops[1].ExpectedSeq = 1
			case "bad_cas":
				ops[1] = makeOp(3, "existing", 0, `{"v":3}`)
			case "bad_value":
				ops[1].Mutations[0].Value = json.RawMessage(`{"bad":true}`)
			}
			frames := make([]Frame, len(ops))
			for i, op := range ops {
				raw, err := json.Marshal(op)
				if err != nil {
					t.Fatal(err)
				}
				frames[i] = Frame{FirstSeq: uint64(op.Seq), Records: []Record{{ID: domain.NewID(), JSON: raw}}}
			}
			clone := func() ControlState {
				rows := map[string]ControlRow{}
				for k, v := range old.Rows {
					rows[k] = v
				}
				return ControlState{Seq: old.Seq, Rows: rows}
			}
			want := clone()
			var referenceErr error
			for _, f := range frames {
				want, referenceErr = applyControlReplay(want, 8, f, validate)
				if referenceErr != nil {
					break
				}
			}
			got, err := applyIndependentReplay(clone(), 8, frames, validate)
			if (err == nil) != (referenceErr == nil) || err == nil && !reflect.DeepEqual(got, want) {
				t.Fatal("replay differs", err, referenceErr, got, want)
			}
		})
	}
}
