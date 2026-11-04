// 準備領域の上限と取消を検査し、取消済みの本文をactorへ渡さない。
package quicv1

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestPreparedWriteCancellationAndBounds(t *testing.T) {
	c := &Conn{ctx: t.Context(), commands: make(chan any, 1)}
	s := newStream(c, 0)
	defer s.cancel()
	for _, invalid := range []int{-1, 0, 65<<10 + 1} {
		if b, err := s.NewWriteBuffer(invalid); err == nil || b != nil {
			t.Fatal("invalid prepared buffer size accepted")
		}
	}
	prepared, err := s.NewWriteBuffer(65 << 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.request.data) > 70<<10 {
		t.Fatal("prepared storage exceeded its bound")
	}
	if err = prepared.Append([]byte("private")); err != nil {
		t.Fatal(err)
	}
	if err = prepared.Append(make([]byte, 65<<10)); err == nil || prepared.request.size != len("private") {
		t.Fatal("overflow partially changed the prepared body")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = prepared.CommitContext(ctx); !errors.Is(err, context.Canceled) || len(c.commands) != 0 {
		t.Fatalf("cancelled body entered the queue: %v", err)
	}
	prepared.Abort()
	if err = prepared.Append([]byte("later")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestPreparedWriteCancellationWhileFlowBlocked(t *testing.T) {
	c := &Conn{ctx: t.Context(), commands: make(chan any, 1), handshakeDone: true, peerMaxData: 32}
	s := newStream(c, 0)
	s.txLimit = 32
	defer s.cancel()
	defer c.releaseBuffers()
	prepared, err := s.NewWriteBuffer(1024)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepared.Append(make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- prepared.CommitContext(ctx) }()
	command := <-c.commands
	if err = c.handleCommand(command); err != nil {
		t.Fatal(err)
	}
	if len(c.blocked) != 1 || c.txTotal != 32 {
		t.Fatal("did not reach the actual flow-control wait")
	}
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP cancellation did not interrupt the prepared write")
	}
	c.processBlocked()
	if len(c.blocked) != 0 || c.txTotal != 32 {
		t.Fatal("cancelled remainder was accepted")
	}
}

// 取消通知を待つgoroutineの実行順にかかわらず、失効後のflow creditで本文を追加しない。
func TestPreparedWriteRevokedDeadlineBeforeMoreCredit(t *testing.T) {
	c := &Conn{ctx: t.Context(), commands: make(chan any, 1), handshakeDone: true, peerMaxData: 32}
	s := newStream(c, 0)
	s.txLimit = 32
	defer s.cancel()
	defer c.releaseBuffers()
	prepared, err := s.NewWriteBuffer(1024)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepared.Append(make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	r := prepared.request
	prepared.request = nil // actorへ所有権を渡し、待機側のtimeout通知を意図的に介在させない。
	r.context, r.done = t.Context(), make(chan error, 1)
	if err = c.handleCommand(r); err != nil {
		t.Fatal(err)
	}
	if c.txTotal != 32 || len(c.blocked) != 1 {
		t.Fatal("write did not block on actual flow credit")
	}
	_ = s.SetWriteDeadline(time.Now().Add(-time.Second))
	c.peerMaxData, s.txLimit = 4096, 4096
	c.processBlocked()
	if c.txTotal != 32 || len(c.blocked) != 0 || !s.resetSent {
		t.Fatal("expired data entered the send queue")
	}
	select {
	case err = <-r.done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	default:
		t.Fatal("deadline error was not returned")
	}
}
