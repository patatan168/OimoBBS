// 確定済みprefixの読取り、上限、取消、Sync不明末尾の隔離を確認する。
package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"testing"
)

type historyFailedSync struct{ *os.File }

func (historyFailedSync) Sync() error { return errors.New("injected sync failure") }
func TestControlCommittedHistory(t *testing.T) {
	dir := filepath.Join(privateTemp(t), "control")
	h := Header{Kind: 2, Owner: domain.NewID(), Generation: 1}
	makeFrame := func(seq domain.U64) []byte {
		t.Helper()
		op := ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: seq - 1, Actor: domain.Actor{Kind: "system", Reason: "bootstrap"}, Mutations: []Mutation{{Collection: "board", Key: "state", ExpectedRevision: seq - 1, Value: json.RawMessage(`{"name":"private value"}`)}}, Result: ControlResult{Code: "updated", Targets: []string{}}}
		raw, _ := json.Marshal(op)
		frame, e := EncodeFrame(Frame{FirstSeq: uint64(seq), Records: []Record{{ID: domain.NewID(), JSON: raw}}})
		if e != nil {
			t.Fatal(e)
		}
		return frame
	}
	log, e := CreateControl(dir, h, makeFrame(1), func(string, string, json.RawMessage, json.RawMessage) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer func() { log.Close() }()
	scan := func(want int) {
		t.Helper()
		count := 0
		budget := HistoryBudget{1 << 20, 100}
		e := log.VisitCommitted(context.Background(), &budget, func(_ Record, op ControlOperation) error {
			count++
			if int(op.Seq) != count {
				t.Fatal("sequence")
			}
			return nil
		})
		if e != nil || count != want {
			t.Fatal("scan", count, e)
		}
	}
	scan(1)
	before, _ := log.file.Seek(0, io.SeekCurrent)
	scan(1)
	after, _ := log.file.Seek(0, io.SeekCurrent)
	if before != after {
		t.Fatal("scan moved writer offset")
	}
	if log.Append(makeFrame(2)).Status != Durable {
		t.Fatal("append after read")
	}
	scan(2)
	for _, budget := range []HistoryBudget{{64, 100}, {1 << 20, 1}} {
		if e := log.VisitCommitted(context.Background(), &budget, func(Record, ControlOperation) error { return nil }); !errors.Is(e, ErrHistoryBudget) {
			t.Fatal("budget", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	budget := HistoryBudget{1 << 20, 100}
	if e := log.VisitCommitted(ctx, &budget, func(Record, ControlOperation) error { return nil }); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation", e)
	}
	log.writer = NewWriter(historyFailedSync{log.file})
	if log.Append(makeFrame(3)).Status != Unknown {
		t.Fatal("injected failure")
	}
	scan(2) // 完全なframeがfileにあっても、稼働中はSync確認済みの2まで。
	log.Close()
	log, e = OpenControl(dir, 2, h.Owner, 0, func(string, string, json.RawMessage, json.RawMessage) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	scan(3) // 復旧で再検証・Syncした後だけ確定分へ含める。
	if _, e = log.file.WriteAt([]byte{0xff}, 64); e != nil {
		t.Fatal(e)
	}
	budget = HistoryBudget{1 << 20, 100}
	if e = log.VisitCommitted(context.Background(), &budget, func(Record, ControlOperation) error { return nil }); e == nil {
		t.Fatal("corrupt history accepted")
	}
}

// 途中のcallback失敗では当該frameを再送し、確定済み位置からだけ続行する。
func TestCommittedCursorResume(t *testing.T) {
	dir := filepath.Join(privateTemp(t), "control")
	h := Header{Kind: 2, Owner: domain.NewID(), Generation: 1}
	makeFrame := func(seq domain.U64) []byte {
		op := ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: seq - 1, Actor: domain.Actor{Kind: "system", Reason: "bootstrap"}, Mutations: []Mutation{{Collection: "board", Key: "state", ExpectedRevision: seq - 1, Value: json.RawMessage(`{}`)}}, Result: ControlResult{Code: "updated", Targets: []string{}}}
		raw, _ := json.Marshal(op)
		frame, _ := EncodeFrame(Frame{FirstSeq: uint64(seq), Records: []Record{{ID: domain.NewID(), JSON: raw}}})
		return frame
	}
	log, e := CreateControl(dir, h, makeFrame(1), func(string, string, json.RawMessage, json.RawMessage) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	if log.Append(makeFrame(2)).Status != Durable {
		t.Fatal("append")
	}
	var cursor HistoryCursor
	budget := HistoryBudget{1 << 20, 100}
	injected := errors.New("sink failure")
	e = log.VisitCommittedFrom(context.Background(), &cursor, &budget, func(_ Record, op ControlOperation) error {
		if op.Seq == 2 {
			return injected
		}
		return nil
	})
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	budget = HistoryBudget{1 << 20, 1}
	count := 0
	e = log.VisitCommittedFrom(context.Background(), &cursor, &budget, func(_ Record, op ControlOperation) error {
		count++
		if op.Seq != 2 {
			t.Fatal(op.Seq)
		}
		return nil
	})
	if e != nil || count != 1 {
		t.Fatal(count, e)
	}
	// 消費済みprefixを読まず、byte/frame予算ゼロでも追いついたことを返せる。
	budget = HistoryBudget{}
	if e = log.VisitCommittedFrom(context.Background(), &cursor, &budget, func(Record, ControlOperation) error { t.Fatal("duplicate"); return nil }); e != nil {
		t.Fatal(e)
	}
	other, e := CreateControl(filepath.Join(privateTemp(t), "control"), h, makeFrame(1), func(string, string, json.RawMessage, json.RawMessage) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = other.VisitCommittedFrom(context.Background(), &cursor, &budget, func(Record, ControlOperation) error { return nil }); !errors.Is(e, ErrCorrupt) {
		t.Fatal("foreign cursor", e)
	}
}
