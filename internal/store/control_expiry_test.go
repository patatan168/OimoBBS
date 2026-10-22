// 満了除去の確定時刻・system認可・一括原子性を再生可能なframeで検査する。
package store

import (
	"encoding/json"
	"os"
	"testing"

	"oimobbs/internal/domain"
)

func TestControlExpiryBoundaryAndAtomicity(t *testing.T) {
	expired := json.RawMessage(`{"expires_at_ns":"100"}`)
	active := json.RawMessage(`{"expires_at_ns":"101"}`)
	state := ControlState{Seq: 1, Rows: map[string]ControlRow{"admin_receipt:a": {Revision: 1, Value: expired}, "admin_receipt:b": {Revision: 1, Value: active}}}
	validator := func(string, string, json.RawMessage, json.RawMessage) error { return nil }
	op := ControlOperation{Schema: 1, Seq: 2, ExpectedSeq: 1, Committed: 100, Actor: domain.Actor{Kind: "system", Reason: "expired_records_cleanup"}, Mutations: []Mutation{{Collection: "admin_receipt", Key: "a", ExpectedRevision: 1, Value: json.RawMessage("null")}}, Result: ControlResult{Code: "expired_records_cleanup", Targets: []string{}}}
	apply := func(op ControlOperation) (ControlState, error) {
		raw, _ := json.Marshal(op)
		return ApplyControl(state, 1, Frame{FirstSeq: 2, Records: []Record{{ID: domain.NewID(), JSON: raw}}}, validator)
	}
	next, e := apply(op)
	if e != nil || len(next.Rows) != 1 || len(state.Rows) != 2 {
		t.Fatal(next, e)
	}
	op.Mutations = append(op.Mutations, Mutation{Collection: "admin_receipt", Key: "b", ExpectedRevision: 1, Value: json.RawMessage("null")})
	next, e = apply(op)
	if e == nil || len(next.Rows) != 2 || len(state.Rows) != 2 {
		t.Fatal("partial expiry transaction", next, e)
	}
	op.Mutations = op.Mutations[:1]
	op.Committed = 99
	if _, e = apply(op); e == nil {
		t.Fatal("premature removal")
	}
	op.Committed = 100
	op.Actor = domain.Actor{Kind: "admin", ID: func() *domain.ID { v := domain.NewID(); return &v }(), Reason: "expired_records_cleanup"}
	if _, e = apply(op); e == nil {
		t.Fatal("manual mutation bypassed expiry owner")
	}
}

func TestControlExpiryFixture(t *testing.T) {
	raw, e := os.ReadFile("../../docs/design/fixtures/runtime-cleanup-delivery.json")
	if e != nil {
		t.Fatal(e)
	}
	var root map[string]json.RawMessage
	if e = json.Unmarshal(raw, &root); e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Expires   domain.Time `json:"expires_at_ns"`
		Committed domain.Time `json:"committed_at_ns"`
		Removable bool        `json:"removable"`
	}
	if e = json.Unmarshal(root["expiry_cases"], &cases); e != nil || len(cases) != 3 {
		t.Fatal(e)
	}
	for _, test := range cases {
		value, _ := json.Marshal(map[string]domain.Time{"expires_at_ns": test.Expires})
		op := ControlOperation{Committed: test.Committed, Actor: domain.Actor{Kind: "system", Reason: "expired_records_cleanup"}, Result: ControlResult{Code: "expired_records_cleanup"}}
		e = validateExpiredControlRemoval(op, Mutation{}, ControlRow{Value: value})
		if (e == nil) != test.Removable {
			t.Fatal("fixture expiry boundary", test, e)
		}
	}
}
