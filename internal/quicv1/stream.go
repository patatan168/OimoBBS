// QUIC streamの公開I/Oを接続actorへ接続し、受信bufferと待機期限を有界にする。
package quicv1

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// StreamError はpeerまたはアプリがstreamを終了した理由。別streamの通信は継続できる。
type StreamError struct {
	Code   uint64
	Remote bool
}

func (e *StreamError) Error() string { return "QUIC stream reset" }

// Stream は片方向または双方向stream。Read/Writeの同時実行は許可し、各方向の複数同時実行は要求しない。
type Stream struct {
	conn                        *Conn
	ctx                         context.Context
	cancel                      context.CancelFunc
	id                          uint64
	mu                          sync.Mutex
	rx                          reassembly
	ready                       []byte
	readErr, writeErr           error
	readDeadline, writeDeadline time.Time
	readChanged, writeChanged   chan struct{}
	writeTimer                  *time.Timer
	writeTimeout                <-chan time.Time
	readConsumed                uint64
	receiveLimit                uint64
	readStopped, writeClosed    bool
	// 次の項目は接続actorだけが操作する。
	txOffset, txLimit uint64
	resetSent         bool
	txFinalAcked      bool
	consumedReported  uint64
	rxStopped         bool
}

func newStream(c *Conn, id uint64) *Stream {
	ctx, cancel := context.WithCancel(c.ctx)
	return &Stream{conn: c, ctx: ctx, cancel: cancel, id: id, rx: reassembly{limit: 64 << 10}, readChanged: make(chan struct{}, 1), writeChanged: make(chan struct{}, 1), receiveLimit: 64 << 10}
}
func (s *Stream) ID() uint64               { return s.id }
func (s *Stream) Context() context.Context { return s.ctx }
func (s *Stream) notifyRead() {
	select {
	case s.readChanged <- struct{}{}:
	default:
	}
}
func (s *Stream) notifyWrite() {
	select {
	case s.writeChanged <- struct{}{}:
	default:
	}
}
func waitIO(ctx context.Context, changed <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-changed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	timer := time.NewTimer(max(time.Duration(0), time.Until(deadline)))
	defer timer.Stop()
	select {
	case <-changed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

// Read は受信済みの連続byteだけを返し、消費した分だけ受信creditを返す。
func (s *Stream) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		select {
		case <-s.readChanged:
		default:
		}
		written := 0
		for written < len(dst) {
			if len(s.ready) == 0 {
				s.ready = s.rx.pop()
			}
			if len(s.ready) == 0 {
				break
			}
			n := copy(dst[written:], s.ready)
			s.ready = s.ready[n:]
			written += n
		}
		if written > 0 {
			s.readConsumed += uint64(written)
			s.mu.Unlock()
			s.conn.consumed(written)
			return written, nil
		}

		err := s.readErr
		if err == nil && s.rx.final != nil && s.rx.next == *s.rx.final {
			err = io.EOF
		}
		changed, deadline := s.readChanged, s.readDeadline
		s.mu.Unlock()
		if err != nil {
			if err == io.EOF {
				_ = s.conn.command(streamCommand{id: s.id, kind: commandReadDone})
			}
			return 0, err
		}
		if err = waitIO(s.ctx, changed, deadline); err != nil {
			return 0, err
		}
	}
}

// Write は有限の送信queueとpeerのflow creditを待つ。期限超過・取消では新規queue投入を止める。
func (s *Stream) Write(data []byte) (int, error) { return s.write(data, false) }

// WriteFinal は末尾のデータとFINを同一の送信要求で確定する。
// 4352byte以下は有限queueへの受理で返す。未送信データにも指定済み期限を適用し、送達確認にはConn.Drainを使う。
func (s *Stream) WriteFinal(data []byte) (int, error) { return s.write(data, true) }
func (s *Stream) write(data []byte, final bool) (int, error) {
	return s.writeVectors([][]byte{data}, final, false)
}

// WriteQueued は4KiB以下の制御データを有限queueへコピーして返す。
// 書込順序と指定済み期限はactorで守り、受理後の失敗はstream終了と次回I/Oで通知する。
// 同じ書込方向の呼出しは直列に行い、送達を待つ場合はConn.Drainを使う。
func (s *Stream) WriteQueued(data []byte) (int, error) {
	if len(data) > 4096 {
		return 0, errors.New("queued control write exceeds budget")
	}
	return s.writeVectors([][]byte{data}, false, true)
}

// Writev はframe prefixと本文を別bufferで受け、QUIC再送用のコピーを一度だけ行う。
// 引数の各bufferは呼出しが返るまで変更しない。
func (s *Stream) Writev(parts ...[]byte) (int, error) { return s.writeVectors(parts, false, false) }

// WriteBufferedv は大きい応答の末尾4352byte以下だけを有限queueへコピーして返す。
// それまでの64KiB単位の書込はflow creditを待つため、本文全体を非同期bufferへ溜めない。
// FINは送らず、アプリの処理終了後にCloseを呼べる。受理後の期限切れはstream終了で通知する。
func (s *Stream) WriteBufferedv(parts ...[]byte) (int, error) {
	return s.writeVectors(parts, false, true)
}

// WriteFinalv はHTTP/3のheader・DATA prefix・本文を中間bufferへ複製せず最終書込へまとめる。
func (s *Stream) WriteFinalv(parts ...[]byte) (int, error) { return s.writeVectors(parts, true, false) }
func (s *Stream) writeVectors(parts [][]byte, final, queued bool) (int, error) {
	length := 0
	for _, part := range parts {
		if len(part) > int(^uint(0)>>1)-length {
			return 0, errors.New("write length overflow")
		}
		length += len(part)
	}
	if length == 0 && final {
		return 0, s.Close()
	}
	total, source, sourceOffset := 0, 0, 0
	for total < length {
		n := min(length-total, 64<<10)
		chunk := s.writeChunk()
		block := getSendBlock(n + ((n+chunk-1)/chunk)*frameHeadroom)
		req := &writeRequest{stream: s, size: n, chunk: chunk, block: block, data: block.data, final: final && total+n == length, asynchronous: (final || queued) && total+n == length && n <= 4352}
		if !req.asynchronous {
			req.done = make(chan error, 1)
		}
		for offset := 0; offset < n; {
			size := min(chunk, n-offset)
			start := (offset/chunk)*(chunk+frameHeadroom) + frameHeadroom
			dst := req.data[start : start+size]
			for len(dst) > 0 {
				for source < len(parts) && sourceOffset == len(parts[source]) {
					source++
					sourceOffset = 0
				}
				copied := copy(dst, parts[source][sourceOffset:])
				sourceOffset += copied
				dst = dst[copied:]
			}
			offset += size
		}
		if err := s.performWrite(req); err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Close は書込方向だけをFINで閉じる。受信済み応答がACKされるまで接続は保持する。
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.writeClosed {
		s.mu.Unlock()
		return nil
	}
	s.writeClosed = true
	s.stopWriteTimer()
	s.mu.Unlock()
	return s.conn.command(streamCommand{id: s.id, kind: commandFIN})
}

// CancelRead は受信を停止し、peerへSTOP_SENDINGを送る。
func (s *Stream) CancelRead(code uint64) {
	s.mu.Lock()
	if s.readStopped {
		s.mu.Unlock()
		return
	}
	s.readStopped = true
	finalKnown := s.rx.final != nil
	s.readErr = &StreamError{Code: code}
	s.ready = nil
	s.rx.parts = nil
	s.rx.buffered = 0
	s.notifyRead()
	s.mu.Unlock()
	kind := commandStop
	if finalKnown {
		kind = commandReadDone
	}
	_ = s.conn.command(streamCommand{id: s.id, kind: kind, code: code})
}

// CancelWrite は未送信の書込方向を打ち切り、最終offset付きRESET_STREAMを送る。
func (s *Stream) CancelWrite(code uint64) {
	s.mu.Lock()
	if s.writeErr != nil {
		s.mu.Unlock()
		return
	}
	s.writeErr = &StreamError{Code: code}
	s.stopWriteTimer()
	s.notifyWrite()
	s.mu.Unlock()
	_ = s.conn.command(streamCommand{id: s.id, kind: commandReset, code: code})
}

// ReadDeadline はQPACKの待機にも同じ読取期限を適用するため現在値を返す。
func (s *Stream) ReadDeadline() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return s.readDeadline }
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.notifyRead()
	s.mu.Unlock()
	return nil
}
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	if t.IsZero() {
		s.stopWriteTimer()
	} else if s.writeTimer != nil {
		s.writeTimer.Reset(max(time.Duration(0), time.Until(t)))
		s.writeTimeout = s.writeTimer.C
	}
	s.notifyWrite()
	s.mu.Unlock()
	return nil
}
func (s *Stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}
func (s *Stream) fail(err error) {
	s.cancel()
	s.mu.Lock()
	if s.readErr == nil {
		s.readErr = err
	}
	if s.writeErr == nil {
		s.writeErr = err
	}
	s.stopWriteTimer()
	s.notifyRead()
	s.notifyWrite()
	s.mu.Unlock()
}

type writeRequest struct {
	context      context.Context
	stream       *Stream
	offset       int
	size         int
	chunk        int
	block        *sendBlock
	data         []byte
	done         chan error
	cancelled    atomic.Bool
	final        bool
	asynchronous bool
	deadline     time.Time
}
type streamCommand struct {
	id, code, value uint64
	kind            int
	done            chan error
	opened          chan *Stream
}

const (
	commandFIN = iota
	commandStop
	commandReset
	commandConsume
	commandOpenUni
	commandClose
	commandReadDone
)

var errClosed = errors.New("QUIC connection closed")

const sendChunk = 1135
const frameHeadroom = 25

// frameData は再送中の区間を書き換えず、専用headroomにSTREAM frame headerを置く。
func (r *writeRequest) frameData(id, offset uint64, n int, fin bool) []byte {
	size := r.chunk
	if size == 0 {
		size = sendChunk
	}
	chunk := r.offset / size
	inside := r.offset % size
	start := chunk * (size + frameHeadroom)
	payload := r.data[start+frameHeadroom+inside : start+frameHeadroom+inside+n]
	kind := uint64(0x0e)
	if fin {
		kind++
	}
	var header [25]byte
	encoded := appendVarint(header[:0], kind)
	encoded = appendVarint(encoded, id)
	encoded = appendVarint(encoded, offset)
	encoded = appendVarint(encoded, uint64(n))
	if inside == 0 && n == min(size, r.size-r.offset) {
		head := start + frameHeadroom - len(encoded)
		copy(r.data[head:start+frameHeadroom], encoded)
		end := start + frameHeadroom + n
		return r.data[head:end:end]
	}
	frame := make([]byte, 0, len(encoded)+n)
	frame = append(frame, encoded...)
	return append(frame, payload...)
}

// submitWrite はactor queueが満杯の場合にも期限変更・取消を反映する。
func (s *Stream) submitWrite(req *writeRequest) error {
	return s.submitWriteContext(req, s.conn.ctx)
}

func (s *Stream) submitWriteContext(req *writeRequest, ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.conn.ctx.Err() != nil {
			return errClosed
		}
		s.mu.Lock()
		select {
		case <-s.writeChanged:
		default:
		}
		err, closed, deadline, changed, timeout := s.writeErr, s.writeClosed, s.writeDeadline, s.writeChanged, s.writeTimeout
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if closed {
			return io.ErrClosedPipe
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		req.deadline = deadline
		select {
		case s.conn.commands <- req:
			return nil
		default:
		}

		s.mu.Lock()
		timeout = s.startWriteTimer()
		s.mu.Unlock()
		select {
		case s.conn.commands <- req:
			return nil
		case <-changed:
			continue
		case <-timeout:
			return os.ErrDeadlineExceeded
		case <-s.conn.ctx.Done():
			return s.conn.ctx.Err()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// startWriteTimer はmutex保持中、実際に待機する書込だけに期限timerを割り当てる。
// queueへ直ちに受理される小応答の期限は接続actorが検証する。
func (s *Stream) startWriteTimer() <-chan time.Time {
	if s.writeDeadline.IsZero() {
		return nil
	}
	if s.writeTimeout == nil {
		if s.writeTimer == nil {
			s.writeTimer = time.NewTimer(max(time.Duration(0), time.Until(s.writeDeadline)))
		} else {
			s.writeTimer.Reset(max(time.Duration(0), time.Until(s.writeDeadline)))
		}
		s.writeTimeout = s.writeTimer.C
	}
	return s.writeTimeout
}

// complete は非同期の最終応答に不要な通知channelを作らず、同期書込だけを起こす。
func (r *writeRequest) complete(err error) {
	if r.done != nil {
		r.done <- err
	}
}

// stopWriteTimer はstreamのmutex保持中に呼び、完了した書込の期限timerを残さない。
func (s *Stream) stopWriteTimer() {
	if s.writeTimer != nil {
		s.writeTimer.Stop()
	}
	s.writeTimeout = nil
}
