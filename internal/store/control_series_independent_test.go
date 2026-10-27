// 非必須256件列の新規行検査・容量拒否・一回同期と再読込みを検査する。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/domain"
	"path/filepath"
	"testing"
)

func TestIndependentSeriesCapacityAndReplay(t *testing.T) {
	plain := func(string, string, json.RawMessage, json.RawMessage) error { return nil }
	header := Header{Kind: 8, Owner: domain.NewID(), Key: 20261024, Generation: 1}
	dir := filepath.Join(privateTemp(t), "journal")
	log, err := CreateControl(dir, header, independentControlFrame(t, 1, "first", json.RawMessage(`{"n":1}`)), plain)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	frames := make([][]byte, MaxCommitSeriesFrames)
	for i := range frames {
		frames[i] = independentControlFrame(t, domain.U64(i+2), fmt.Sprintf("entry%d", i), json.RawMessage(`{"n":2}`))
	}
	before := log.CommitStats()
	denied := errors.New("capacity")
	if r := log.AppendIndependentSeriesChecked(frames, func(int64) error { return denied }); r.Status != NotWritten || !errors.Is(r.Err, denied) || log.State().Seq != 1 || log.CommitStats() != before {
		t.Fatal("capacity refusal wrote", r)
	}
	if r := log.AppendIndependentSeriesChecked(frames, nil); r.Status != Durable || log.State().Seq != 257 || log.CommitStats().Syncs-before.Syncs != 1 {
		t.Fatal(r)
	}
	before = log.CommitStats()
	if r := log.AppendIndependentSeriesChecked(frames, nil); r.Status != NotWritten || log.CommitStats() != before {
		t.Fatal("existing keys accepted", r)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenControl(dir, 8, header.Owner, header.Key, plain)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.State().Seq != 257 || len(reopened.State().Rows) != 257 {
		t.Fatal("series recovery")
	}
}
