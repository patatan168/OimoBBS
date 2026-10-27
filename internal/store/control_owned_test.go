// 所有状態の差分反映が、外へ渡した旧状態と保存失敗時の原子性を保つことを検査する。
package store

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"oimobbs/internal/domain"
)

func TestControlOwnedAppendAtomicity(t *testing.T) {
	for _, failure := range []string{"none", "sync", "invalid"} {
		t.Run(failure, func(t *testing.T) {
			old, op := controlReplayFixture(t)
			baseline, _ := json.Marshal(old)
			writer := &faultWriter{}
			if failure == "sync" {
				writer.syncErr = errors.New("sync failed")
			}
			if failure == "invalid" {
				op.Mutations[1].ExpectedRevision++
			}
			frame := controlReplayFrame(t, op)
			prepared, e := EncodeFrame(frame)
			if e != nil {
				t.Fatal(e)
			}
			validate := func(_, _ string, _, next json.RawMessage) error { return validateControlReplayValue(next) }
			log := &ControlLog{header: Header{Kind: 9}, state: old, validator: validate, writer: NewWriter(writer)}
			expected, expectedErr := ApplyControl(old, 9, frame, validate)
			result := log.Append(prepared)
			if failure == "none" {
				saved, _ := json.Marshal(log.state)
				for i := range prepared {
					prepared[i] = 0
				}
				actual, _ := json.Marshal(log.state)
				if string(saved) != string(actual) {
					t.Fatal("追記元bufferの再利用が確定状態へ波及した")
				}
				if result.Status != Durable || expectedErr != nil || !reflect.DeepEqual(log.state, expected) {
					t.Fatal("owned append differs from immutable apply", result, expectedErr)
				}
				return
			}
			actual, _ := json.Marshal(log.state)
			if string(actual) != string(baseline) || failure == "sync" && result.Status != Unknown || failure == "invalid" && (result.Status != NotWritten || writer.writes != 0) {
				t.Fatal("failed append modified state", result)
			}
		})
	}
}

func TestControlOwnedAppendKeepsExposedState(t *testing.T) {
	old, op := controlReplayFixture(t)
	validate := func(_, _ string, _, next json.RawMessage) error { return validateControlReplayValue(next) }
	log := &ControlLog{header: Header{Kind: 9}, state: old, validator: validate, writer: NewWriter(&faultWriter{})}
	before := log.State()
	baseline, _ := json.Marshal(before)
	for seq := domain.U64(10); seq <= 12; seq++ {
		op.Seq, op.ExpectedSeq = seq, seq-1
		op.Mutations = []Mutation{{Collection: "transfer", Key: "new", ExpectedRevision: func() domain.U64 {
			if seq == 10 {
				return 0
			}
			return seq - 1
		}(), Value: json.RawMessage(`{"v":2}`)}}
		prepared, e := EncodeFrame(controlReplayFrame(t, op))
		if e != nil || log.Append(prepared).Status != Durable {
			t.Fatal("append", e)
		}
		actual, _ := json.Marshal(before)
		if string(actual) != string(baseline) {
			t.Fatal("later append changed exposed snapshot")
		}
	}
	if log.State().Seq != 12 || len(log.state.Rows) != 10001 {
		t.Fatal("unrelated rows lost")
	}
}

func TestControlOwnedSnapshotDuringValidation(t *testing.T) {
	old, op := controlReplayFixture(t)
	baseline, _ := json.Marshal(old)
	log := &ControlLog{header: Header{Kind: 9}, state: old, writer: NewWriter(&faultWriter{})}
	var captured ControlState
	log.validator = func(_, _ string, _, next json.RawMessage) error {
		captured = log.State()
		return validateControlReplayValue(next)
	}
	prepared, e := EncodeFrame(controlReplayFrame(t, op))
	if e != nil || log.Append(prepared).Status != Durable {
		t.Fatal(e)
	}
	actual, _ := json.Marshal(captured)
	if string(actual) != string(baseline) || len(log.state.Rows) != 9999 {
		t.Fatal("snapshot acquired during validation changed")
	}
}

func TestControlOwnedBatchOverlappingRows(t *testing.T) {
	for _, mode := range []string{"owned", "exposed", "capture", "invalid", "sync"} {
		t.Run(mode, func(t *testing.T) {
			old, op := controlReplayFixture(t)
			baseline, _ := json.Marshal(old)
			writer := &faultWriter{}
			if mode == "sync" {
				writer.syncErr = errors.New("sync failed")
			}
			validate := func(_, _ string, _, next json.RawMessage) error { return validateControlReplayValue(next) }
			log := &ControlLog{header: Header{Kind: 9}, state: old, validator: validate, writer: NewWriter(writer)}
			var exposed ControlState
			if mode == "exposed" {
				exposed = log.State()
			}
			if mode == "capture" {
				log.validator = func(collection, key string, previous, next json.RawMessage) error {
					exposed = log.State()
					return validate(collection, key, previous, next)
				}
			}
			expected := old
			var frames [][]byte
			for index, value := range []string{`{"v":2}`, `null`, `{"v":3}`} {
				op.Seq, op.ExpectedSeq = domain.U64(10+index), domain.U64(9+index)
				revision := domain.U64(1)
				if index == 1 {
					revision = 10
				} else if index == 2 {
					revision = 0
				}
				op.Mutations = []Mutation{{Collection: "transfer", Key: "k1", ExpectedRevision: revision, Value: json.RawMessage(value)}}
				if index == 2 && mode == "invalid" {
					op.Mutations[0].ExpectedRevision = 11
				}
				frame := controlReplayFrame(t, op)
				prepared, e := EncodeFrame(frame)
				if e != nil {
					t.Fatal(e)
				}
				frames = append(frames, prepared)
				if mode != "invalid" {
					expected, e = ApplyControl(expected, 9, frame, validate)
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			result := log.AppendBatch(frames)
			if mode == "invalid" || mode == "sync" {
				actual, _ := json.Marshal(log.state)
				if string(actual) != string(baseline) || mode == "invalid" && (result.Status != NotWritten || writer.writes != 0) || mode == "sync" && result.Status != Unknown {
					t.Fatal("failed batch changed state", result)
				}
				return
			}
			if result.Status != Durable || !reflect.DeepEqual(log.state, expected) || writer.writes != 1 {
				t.Fatal("overlapping batch differs from immutable apply", result)
			}
			if mode == "exposed" || mode == "capture" {
				actual, _ := json.Marshal(exposed)
				if string(actual) != string(baseline) {
					t.Fatal("batch modified exposed snapshot")
				}
			}
		})
	}
}
