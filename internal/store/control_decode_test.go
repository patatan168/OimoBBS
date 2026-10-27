// 解析済み制御操作の保存が通常適用と同じ検証・失敗境界を保つことを検査する。
package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"oimobbs/internal/domain"
)

func FuzzControlAppendMatchesApply(f *testing.F) {
	op := ControlOperation{Schema: 1, Seq: 1, Actor: domain.Actor{Kind: "system", Reason: "test"}, Mutations: []Mutation{{Collection: "board", Key: "state", Value: json.RawMessage(`{"v":1}`)}}, Result: ControlResult{Code: "updated", Targets: []string{}}}
	raw, _ := json.Marshal(op)
	f.Add(raw, []byte{})
	f.Add(bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1), []byte{})
	f.Add(raw, []byte("unexpected DAT"))
	f.Add([]byte(`{}`), []byte{})
	f.Fuzz(func(t *testing.T, raw, dat []byte) {
		if len(raw)+len(dat) > 8192 {
			return
		}
		frame := Frame{FirstSeq: 1, Records: []Record{{ID: domain.ID{1}, JSON: raw, DAT: dat}}}
		encoded, e := EncodeFrame(frame)
		if e != nil {
			return
		}
		validate := func(_, _ string, _, next json.RawMessage) error { return validateControlReplayValue(next) }
		old := ControlState{Rows: map[string]ControlRow{"board:untouched": {Revision: 1, Value: json.RawMessage(`{"v":2}`)}}}
		before, _ := json.Marshal(old)
		want, applyErr := ApplyControl(old, 2, frame, validate)
		for _, batch := range []bool{false, true} {
			writer := &faultWriter{}
			log := &ControlLog{header: Header{Kind: 2}, state: old, validator: validate, writer: NewWriter(writer)}
			_ = log.State()
			var result CommitResult
			if batch {
				result = log.AppendBatch([][]byte{encoded})
			} else {
				result = log.Append(encoded)
			}
			if applyErr != nil {
				if result.Status != NotWritten || writer.writes != 0 {
					t.Fatal("invalid input written", batch, result)
				}
			} else if result.Status != Durable || !reflect.DeepEqual(log.state, want) {
				t.Fatal("apply differs from append", batch, result)
			}
			if applyErr != nil {
				actual, _ := json.Marshal(log.state)
				if !bytes.Equal(actual, before) {
					t.Fatal("failed append changed state")
				}
			}
			actual, _ := json.Marshal(old)
			if !bytes.Equal(actual, before) {
				t.Fatal("old state changed")
			}
		}
	})
}

func BenchmarkControlAppendBatch(b *testing.B) {
	for _, count := range []int{1, 16, 64} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			var frames [][]byte
			for seq := 1; seq <= count; seq++ {
				op := ControlOperation{Schema: 1, Seq: domain.U64(seq), ExpectedSeq: domain.U64(seq - 1), Actor: domain.Actor{Kind: "system", Reason: "benchmark"}, Mutations: []Mutation{{Collection: "board", Key: fmt.Sprint("row", seq), Value: json.RawMessage(`{"body":"` + strings.Repeat("a", 4096) + `"}`)}}, Result: ControlResult{Code: "updated", Targets: []string{}}}
				raw, e := json.Marshal(op)
				if e != nil {
					b.Fatal(e)
				}
				frame, e := EncodeFrame(Frame{FirstSeq: uint64(seq), Records: []Record{{ID: domain.ID{1}, JSON: raw}}})
				if e != nil {
					b.Fatal(e)
				}
				frames = append(frames, frame)
			}
			validate := func(_, _ string, _, _ json.RawMessage) error { return nil }
			b.ReportAllocs()
			for b.Loop() {
				log := &ControlLog{header: Header{Kind: 2}, state: ControlState{Rows: map[string]ControlRow{}}, validator: validate, writer: NewWriter(&faultWriter{})}
				if result := log.AppendBatch(frames); result.Status != Durable {
					b.Fatal(result)
				}
			}
		})
	}
}
