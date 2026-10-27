// 一括保存の耐久境界・不変状態・再起動時の整合性を検査する。
package store

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"path/filepath"
	"testing"
)

type batchSyncWriter struct {
	*faultWriter
	syncs int
}

func (w *batchSyncWriter) Sync() error { w.syncs++; return w.syncErr }

func TestControlBatchDurabilityAndRecovery(t *testing.T) {
	makeFrame := func(seq domain.U64) []byte {
		op := ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: seq - 1, Actor: domain.Actor{Kind: "system", Reason: "test"}, Mutations: []Mutation{{Collection: "board", Key: "state", ExpectedRevision: seq - 1, Value: json.RawMessage(`{"name":"test"}`)}}, Result: ControlResult{Code: "updated", Targets: []string{}}}
		raw, _ := json.Marshal(op)
		frame, e := EncodeFrame(Frame{FirstSeq: uint64(seq), Records: []Record{{ID: domain.NewID(), JSON: raw}}})
		if e != nil {
			t.Fatal(e)
		}
		return frame
	}
	validate := func(string, string, json.RawMessage, json.RawMessage) error { return nil }
	for _, failure := range []string{"none", "sync", "short", "write", "invalid"} {
		t.Run(failure, func(t *testing.T) {
			h := Header{Kind: 2, Owner: domain.NewID(), Generation: 1}
			dir := filepath.Join(privateTemp(t), "control")
			log, e := CreateControl(dir, h, makeFrame(1), validate)
			if e != nil {
				t.Fatal(e)
			}
			before := log.State()
			frames := [][]byte{makeFrame(2), makeFrame(3), makeFrame(4)}
			mock := &batchSyncWriter{faultWriter: &faultWriter{}}
			if failure == "sync" {
				mock.syncErr = errors.New("sync")
			}
			if failure == "write" {
				mock.writeErr = errors.New("write")
			}
			if failure == "short" {
				mock.short = true
			}
			if failure == "invalid" {
				frames[2] = makeFrame(6)
			}
			if failure != "none" {
				log.writer = NewWriter(mock)
			}
			result := log.AppendBatch(frames)
			if before.Seq != 1 || before.Rows["board:state"].Revision != 1 {
				t.Fatal("old snapshot modified")
			}
			if failure == "none" {
				if result.Status != Durable || log.State().Seq != 4 {
					t.Fatal(result)
				}
				log.Close()
				log, e = OpenControl(dir, 2, h.Owner, 0, validate)
				if e != nil || log.State().Seq != 4 {
					t.Fatal("recovery", e)
				}
			} else if failure == "invalid" {
				if result.Status != NotWritten || mock.writes != 0 || log.State().Seq != 1 {
					t.Fatal(result, mock.writes)
				}
			} else {
				if result.Status != Unknown || log.State().Seq != 1 || mock.writes != 1 {
					t.Fatal(result)
				}
				if log.AppendBatch(frames).Status != Unknown || mock.writes != 1 {
					t.Fatal("resumed after unknown")
				}
			}
			log.Close()
		})
	}
	// 複数frameでも一度のWrite/Sync。途中frameが不正なら書込なし。
	frames := [][]byte{makeFrame(1), makeFrame(2), makeFrame(3)}
	w := &batchSyncWriter{faultWriter: &faultWriter{}}
	if NewWriter(w).CommitBatch(frames).Status != Durable || w.writes != 1 || w.syncs != 1 {
		t.Fatal("not grouped", w.writes, w.syncs)
	}
	w = &batchSyncWriter{faultWriter: &faultWriter{}}
	frames[2] = frames[2][:len(frames[2])-1]
	if NewWriter(w).CommitBatch(frames).Status != NotWritten || w.writes != 0 {
		t.Fatal("invalid tail written")
	}
}

// 保存不明の完全frameと途中末尾を、通常の復旧で個別に再検証する。
func TestControlBatchUnknownAndPartialTailRecovery(t *testing.T) {
	validate := func(string, string, json.RawMessage, json.RawMessage) error { return nil }
	makeFrame := func(seq domain.U64) []byte {
		op := ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: seq - 1, Actor: domain.Actor{Kind: "system", Reason: "test"}, Mutations: []Mutation{{Collection: "board", Key: "state", ExpectedRevision: seq - 1, Value: json.RawMessage(`{"name":"test"}`)}}, Result: ControlResult{Code: "updated", Targets: []string{}}}
		raw, _ := json.Marshal(op)
		frame, e := EncodeFrame(Frame{FirstSeq: uint64(seq), Records: []Record{{ID: domain.NewID(), JSON: raw}}})
		if e != nil {
			t.Fatal(e)
		}
		return frame
	}
	for _, partial := range []bool{false, true} {
		dir := filepath.Join(privateTemp(t), "control")
		h := Header{Kind: 2, Owner: domain.NewID(), Generation: 1}
		log, e := CreateControl(dir, h, makeFrame(1), validate)
		if e != nil {
			t.Fatal(e)
		}
		frames := [][]byte{makeFrame(2), makeFrame(3)}
		want := domain.U64(3)
		if partial {
			if _, e = log.file.Write(append(frames[0], frames[1][:len(frames[1])/2]...)); e != nil {
				t.Fatal(e)
			}
			want = 2
		} else {
			log.writer = NewWriter(historyFailedSync{log.file})
			if result := log.AppendBatch(frames); result.Status != Unknown || log.State().Seq != 1 {
				t.Fatal(result)
			}
		}
		log.Close()
		log, e = OpenControl(dir, 2, h.Owner, 0, validate)
		if e != nil {
			t.Fatal(e)
		}
		if log.State().Seq != want {
			t.Fatal("recovery sequence", log.State().Seq, want)
		}
		if result := log.Append(makeFrame(want + 1)); result.Status != Durable {
			t.Fatal("append after recovery", result)
		}
		log.Close()
	}
}
