// 途中mutationの失敗、所有単位の混同、キー予約の逆行を検査する。
package store

import (
	"encoding/json"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"testing"
)

func TestControlAtomicity(t *testing.T) {
	op := ControlOperation{Schema: 1, Seq: 1, Actor: domain.Actor{Kind: "system", Reason: "bootstrap"}, Mutations: []Mutation{{Collection: "key_watermark", Key: "thread", Value: json.RawMessage(`{"last_reserved_key":"1"}`)}, {Collection: "bump_watermark", Key: "ranking", Value: json.RawMessage(`{"last_removed_bump":"1"}`)}}, Result: ControlResult{Code: "created", Targets: []string{}}}
	validator := func(collection, key string, old, next json.RawMessage) error {
		var v struct {
			Last domain.U64 `json:"last_reserved_key"`
		}
		return strictjson.Decode(next, &v)
	}
	b, _ := json.Marshal(op)
	old := ControlState{Rows: map[string]ControlRow{}}
	frame := Frame{1, []Record{{domain.NewID(), b, nil}}}
	next, e := ApplyControl(old, 2, frame, validator)
	if e == nil || len(old.Rows) != 0 || len(next.Rows) != 0 {
		t.Fatal("partial mutation published")
	}
	op.Mutations = op.Mutations[:1]
	b, _ = json.Marshal(op)
	frame.Records[0].JSON = b
	next, e = ApplyControl(old, 2, frame, validator)
	if e != nil || len(next.Rows) != 1 || next.Seq != 1 {
		t.Fatal(next, e)
	}
	if _, e = ApplyControl(old, 1, frame, validator); e == nil {
		t.Fatal("wrong owner kind")
	}
	if _, e = ApplyControl(next, 2, frame, validator); e == nil {
		t.Fatal("old revision accepted")
	}
}
func TestKeyReservation(t *testing.T) {
	for _, v := range []struct {
		Last uint64
		Now  int64
		Want uint64
	}{{0, -1, 1}, {10, 3, 11}, {10, 100, 100}} {
		got, e := NextThreadKey(v.Last, v.Now)
		if e != nil || got != v.Want {
			t.Fatal(got, e)
		}
	}
	if _, e := NextThreadKey(math.MaxUint64, 0); e == nil {
		t.Fatal("overflow")
	}
}

func TestControlDiskHighWatermark(t *testing.T) {
	dir := filepath.Join(privateTemp(t), "control")
	owner := domain.NewID()
	validate := func(collection, key string, old, next json.RawMessage) error {
		if collection != "key_watermark" || key != "thread" {
			return ErrCorrupt
		}
		var v struct {
			Last domain.U64 `json:"last_reserved_key"`
		}
		if e := strictjson.Decode(next, &v); e != nil {
			return e
		}
		if old != nil {
			var prior struct {
				Last domain.U64 `json:"last_reserved_key"`
			}
			if e := strictjson.Decode(old, &prior); e != nil {
				return e
			}
			if v.Last <= prior.Last {
				return ErrCorrupt
			}
		}
		return nil
	}
	op := ControlOperation{Schema: 1, Seq: 1, Actor: domain.Actor{Kind: "system", Reason: "key_reservation"}, Mutations: []Mutation{{Collection: "key_watermark", Key: "thread", Value: json.RawMessage(`{"last_reserved_key":"100"}`)}}, Result: ControlResult{Code: "reserved", Targets: []string{"100"}}}
	raw, _ := json.Marshal(op)
	frame, _ := EncodeFrame(Frame{1, []Record{{domain.NewID(), raw, nil}}})
	log, e := CreateControl(dir, Header{Kind: 2, Owner: owner, Generation: 1}, frame, validate)
	if e != nil {
		t.Fatal(e)
	}
	op.Seq = 2
	op.ExpectedSeq = 1
	op.Mutations[0].ExpectedRevision = 1
	op.Mutations[0].Value = json.RawMessage(`{"last_reserved_key":"101"}`)
	op.Result.Targets = []string{"101"}
	raw, _ = json.Marshal(op)
	frame, _ = EncodeFrame(Frame{2, []Record{{domain.NewID(), raw, nil}}})
	if r := log.Append(frame); r.Status != Durable {
		t.Fatal(r)
	}
	_ = log.Close()
	log, e = OpenControl(dir, 2, owner, 0, validate)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	if log.State().Seq != 2 || string(log.State().Rows["key_watermark:thread"].Value) != `{"last_reserved_key":"101"}` {
		t.Fatal(log.State())
	}
	if _, e = OpenControl(dir, 1, owner, 0, validate); e == nil {
		t.Fatal("cross-kind recovery")
	}
}
