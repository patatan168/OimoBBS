// UDPの部分送信とGSO失敗で、送達済みdatagramを重複送信しないことを検証する。
package quicv1

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"golang.org/x/net/ipv4"
)

type batchResult struct {
	n   int
	err error
}

type scriptedBatchWriter struct {
	t       *testing.T
	results []batchResult
	sent    [][]byte
}

func (w *scriptedBatchWriter) WriteBatch(messages []ipv4.Message, _ int) (int, error) {
	w.t.Helper()
	if len(w.results) == 0 {
		w.t.Fatal("unexpected batch write")
	}
	result := w.results[0]
	w.results = w.results[1:]
	if result.n > len(messages) {
		w.t.Fatal("invalid scripted write count")
	}
	for _, message := range messages[:result.n] {
		w.sent = append(w.sent, bytes.Join(message.Buffers, nil))
	}
	return result.n, result.err
}

func TestUDPGSOPartialWriteFallback(t *testing.T) {
	if len(gsoControl(1200)) == 0 {
		t.Skip("OS has no GSO control")
	}
	packets := [][]byte{bytes.Repeat([]byte{1}, 1200), bytes.Repeat([]byte{2}, 1200), {3}, bytes.Repeat([]byte{4}, 1200), bytes.Repeat([]byte{5}, 1200), {6}}
	writer := &scriptedBatchWriter{t: t, results: []batchResult{{1, errors.New("GSO unsupported")}, {1, nil}, {2, nil}}}
	l := &Listener{}
	var batch udpBatch
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
	if err := l.sendBatchWith(packets, nil, addr, addr, &batch, writer); err != nil {
		t.Fatal(err)
	}
	want := [][]byte{bytes.Join(packets[:3], nil), packets[3], packets[4], packets[5]}
	if !l.gsoDisabled.Load() || len(writer.results) != 0 || len(writer.sent) != len(want) {
		t.Fatal("fallback or partial progress was lost")
	}
	for i := range want {
		if !bytes.Equal(writer.sent[i], want[i]) {
			t.Fatalf("message %d duplicated or omitted datagrams", i)
		}
	}
	for i := range batch.messages {
		if batch.messages[i].Buffers != nil || batch.messages[i].Addr != nil || batch.single[i] != nil {
			t.Fatal("sender workspace retained packet or endpoint")
		}
	}
}

func TestUDPBatchWriteFailure(t *testing.T) {
	for _, writeErr := range []error{nil, errors.New("socket failed")} {
		writer := &scriptedBatchWriter{t: t, results: []batchResult{{0, writeErr}}}
		l := &Listener{}
		l.gsoDisabled.Store(true)
		var batch udpBatch
		addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
		if err := l.sendBatchWith([][]byte{{1}, {2}}, nil, addr, addr, &batch, writer); err == nil {
			t.Fatal("failed or empty batch write accepted")
		}
	}
}
