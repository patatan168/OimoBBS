// アプリが小分けで渡す確定済み本文を、再送用bufferへ一度だけコピーしてから送信する。
package quicv1

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

// WriteBuffer は最大65KiBの準備領域。AppendはI/Oせず、Commitで通常のflow制御と期限を待つ。
// 同じstreamへの他のWriteとは交互に使わず、使わなかった領域はAbortで解放する。
type WriteBuffer struct {
	request *writeRequest
	limit   int
}

// NewWriteBuffer は有限の再送用領域を確保する。本文と小さいframe prefixだけを対象にする。
func (s *Stream) NewWriteBuffer(limit int) (*WriteBuffer, error) {
	if limit < 1 || limit > 65<<10 {
		return nil, errors.New("QUIC prepared write bound")
	}
	if err := s.checkWriteState(); err != nil {
		return nil, err
	}
	chunk := s.writeChunk()
	block := getSendBlock(limit + ((limit+chunk-1)/chunk)*frameHeadroom)
	if s.conn.listener != nil {
		s.conn.listener.preparedWrites.Add(1)
	}
	r := &writeRequest{stream: s, chunk: chunk, block: block, data: block.data}
	return &WriteBuffer{request: r, limit: limit}, nil
}

// Append は所有する領域へコピーする。元のsliceは呼出し直後から再利用できる。
func (b *WriteBuffer) Append(parts ...[]byte) error {
	r := b.request
	if r == nil {
		return io.ErrClosedPipe
	}
	if err := r.stream.checkWriteState(); err != nil {
		return err
	}
	remaining := b.limit - r.size
	for _, part := range parts {
		if len(part) > remaining {
			return errors.New("QUIC prepared write overflow")
		}
		remaining -= len(part)
	}
	for _, part := range parts {
		for len(part) > 0 {
			inside := r.size % r.chunk
			start := (r.size/r.chunk)*(r.chunk+frameHeadroom) + frameHeadroom + inside
			n := min(len(part), r.chunk-inside)
			copy(r.data[start:start+n], part[:n])
			r.size += n
			part = part[n:]
		}
	}
	return nil
}

// Commit はbufferの所有権をactorへ移し、準備済みbyteがflow制御付きqueueへ入るまで待つ。
// FINは付けず、handlerの終了とstream contextの終了を前倒ししない。
func (b *WriteBuffer) Commit() error {
	if b.request == nil {
		return io.ErrClosedPipe
	}
	return b.CommitContext(b.request.stream.Context())
}

// CommitContext は追加の要求取消も、queue待ち・flow待ち・actorによる受理の直前まで確認する。
func (b *WriteBuffer) CommitContext(ctx context.Context) error {
	r := b.request
	if r == nil {
		return io.ErrClosedPipe
	}
	b.request = nil
	if r.size == 0 {
		r.block.release()
		return nil
	}
	return r.stream.performWriteContext(r, ctx)
}

// Abort はまだactorへ渡していない領域だけを解放する。Commit後も安全に呼べる。
func (b *WriteBuffer) Abort() {
	if b.request != nil {
		b.request.block.release()
		b.request = nil
	}
}

func (s *Stream) writeChunk() int {
	chunk := int(s.conn.chunkSize.Load())
	if chunk == 0 {
		return sendChunk
	}
	var encoded [8]byte
	return chunk + 8 - len(appendVarint(encoded[:0], s.id))
}

// checkWriteState は準備中も期限・接続取消・peer resetを反映する。
func (s *Stream) checkWriteState() error {
	s.mu.Lock()
	err, closed, deadline := s.writeErr, s.writeClosed, s.writeDeadline
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if closed {
		return io.ErrClosedPipe
	}
	if s.conn.ctx.Err() != nil {
		return errClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// performWrite は通常・準備済みの両方に同じqueue・期限・取消を適用する。
// submit成功後の領域はactorが所有し、呼出元は変更・解放しない。
func (s *Stream) performWrite(r *writeRequest) error {
	return s.performWriteContext(r, s.conn.ctx)
}

func (s *Stream) performWriteContext(r *writeRequest, ctx context.Context) error {
	r.context = ctx
	if !r.asynchronous && r.done == nil {
		r.done = make(chan error, 1)
	}
	if err := s.submitWriteContext(r, ctx); err != nil {
		r.block.release()
		return err
	}
	if r.asynchronous {
		s.mu.Lock()
		if r.final {
			s.writeClosed = true
		}
		s.stopWriteTimer()
		s.mu.Unlock()
		return nil
	}
	for {
		s.mu.Lock()
		select {
		case <-s.writeChanged:
		default:
		}
		changed, timeout, err := s.writeChanged, s.startWriteTimer(), s.writeErr
		s.mu.Unlock()
		if err != nil {
			r.cancelled.Store(true)
			return err
		}
		select {
		case err := <-r.done:
			if err == nil && r.final {
				s.mu.Lock()
				s.writeClosed = true
				s.stopWriteTimer()
				s.mu.Unlock()
			}
			return err
		case <-changed:
		case <-timeout:
			r.cancelled.Store(true)
			return os.ErrDeadlineExceeded
		case <-s.conn.ctx.Done():
			r.cancelled.Store(true)
			return s.conn.ctx.Err()
		case <-ctx.Done():
			r.cancelled.Store(true)
			return ctx.Err()
		}
	}
}
