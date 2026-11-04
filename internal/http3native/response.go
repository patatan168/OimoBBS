// net/http ResponseWriterをHTTP/3 HEADERS/DATAへ変換する。小さい応答はFINまでまとめる。
package http3native

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"oimobbs/internal/quicv1"
)

type responseBuffer struct{ data [4096]byte }

var responseBuffers = sync.Pool{New: func() any { return new(responseBuffer) }}

type responseWriter struct {
	bufferOwner *responseBuffer
	stream      *quicv1.Stream
	qpack       *QPACK
	connection  *connection
	request     *http.Request
	header      http.Header
	snapshot    http.Header
	status      int
	sent        bool
	buffer      []byte
	written     int64
	err         error
	bodyHint    int
	bodyBuffer  *quicv1.WriteBuffer
	bodyFramed  bool
}

func (w *responseWriter) Header() http.Header { return w.header }
func (w *responseWriter) WriteHeader(status int) {
	if status < 100 || status > 999 {
		panic("invalid HTTP status")
	}
	if w.status != 0 {
		return
	}
	if status < 200 {
		if status == 101 {
			panic("HTTP/3 cannot switch protocols")
		}
		work := headerWorkPool.Get().(*headerWork)
		defer work.release()
		block, err := w.headerBlock(status, w.header, work)
		if err == nil {
			_, err = w.stream.Writev(work.prefix(len(block)), block)
		}
		w.err = err
		return
	}
	w.status = status
	w.snapshot = w.header.Clone()
}
func (w *responseWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.status == 0 {
		w.WriteHeader(200)
	}
	if !bodyAllowed(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	if w.snapshot.Get("Content-Type") == "" && w.snapshot.Get("Content-Encoding") == "" && len(data) > 0 {
		if _, exists := w.snapshot["Content-Type"]; !exists {
			w.snapshot.Set("Content-Type", http.DetectContentType(data))
		}
	}
	complete := false
	if value := w.snapshot.Get("Content-Length"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 || w.written+int64(len(data)) > n {
			return 0, http.ErrContentLength
		}
		complete = w.written+int64(len(data)) == n
	}
	w.written += int64(len(data))
	if w.request.Method == "HEAD" {
		return len(data), nil
	}
	if w.bodyBuffer != nil {
		if err := w.bodyBuffer.Append(data); err != nil {
			w.err = err
			return 0, err
		}
		if complete {
			w.err = w.commitBodyBuffer()
		}
		return len(data), w.err
	}
	if !w.sent && len(w.buffer)+len(data) <= 4096 {
		if w.bufferOwner == nil {
			w.bufferOwner = responseBuffers.Get().(*responseBuffer)
			w.buffer = w.bufferOwner.data[:0]
		}
		w.buffer = append(w.buffer, data...)
		return len(data), nil
	}
	if !w.sent {
		// 既知の本文長を満たす最終Writeだけは小さい端数をqueueへ預ける。
		// FINはhandler終了まで遅らせ、要求contextの寿命を保つ。
		if err := w.writeHeaders(false, data, complete); err != nil {
			return 0, err
		}
		return len(data), nil
	}
	if len(w.buffer) > 0 {
		if _, err := w.stream.Writev(dataPrefix(len(w.buffer)), w.buffer); err != nil {
			w.err = err
			return 0, err
		}
		w.buffer = nil
	}
	if len(data) > 0 {
		var err error
		if w.bodyFramed {
			_, err = w.stream.Write(data)
		} else {
			_, err = w.stream.Writev(dataPrefix(len(data)), data)
		}
		if err != nil {
			w.err = err
			return 0, err
		}
	}
	return len(data), nil
}
func bodyAllowed(status int) bool { return status >= 200 && status != 204 && status != 304 }
func (w *responseWriter) flushHeaders(final bool) error {
	return w.writeHeaders(final, nil, false)
}

// writeHeaders はHEADERSと最初のDATAを同じQUIC書込へまとめ、独立したI/O待ちを避ける。
func (w *responseWriter) writeHeaders(final bool, tail []byte, bufferedTail bool) error {
	if w.err != nil {
		return w.err
	}
	if w.sent {
		return nil
	}
	if w.status == 0 {
		w.WriteHeader(200)
	}
	if _, exists := w.snapshot["Date"]; !exists {
		w.snapshot.Set("Date", httpDate(time.Now()))
	}
	if final && bodyAllowed(w.status) && w.request.Method != "HEAD" {
		if _, exists := w.snapshot["Content-Length"]; !exists {
			w.snapshot.Set("Content-Length", strconv.FormatInt(w.written, 10))
		}
	}
	if w.status == 204 {
		w.snapshot.Del("Content-Length")
	}
	if w.status == 304 {
		w.snapshot.Del("Content-Type")
		w.snapshot.Del("Content-Encoding")
	}
	work := headerWorkPool.Get().(*headerWork)
	defer work.release()
	block, err := w.headerBlock(w.status, w.snapshot, work)
	if err != nil {
		w.err = err
		return err
	}
	prefix := work.prefix(len(block))
	if !final && len(w.buffer)+len(tail) > 0 {
		if handled, err := w.prepareBodyFrame(prefix, block, tail); handled {
			w.err = err
			return err
		}
	}
	if len(w.buffer)+len(tail) > 0 {
		dataHeader := dataPrefix(len(w.buffer) + len(tail))
		if final {
			_, err = w.stream.WriteFinalv(prefix, block, dataHeader, w.buffer, tail)
		} else if bufferedTail {
			_, err = w.stream.WriteBufferedv(prefix, block, dataHeader, w.buffer, tail)
		} else {
			_, err = w.stream.Writev(prefix, block, dataHeader, w.buffer, tail)
		}
		w.buffer = nil
	} else if final {
		_, err = w.stream.WriteFinalv(prefix, block)
	} else {
		_, err = w.stream.Writev(prefix, block)
	}

	w.sent = true
	w.err = err
	return err
}

// FlushError はResponseControllerから呼ばれ、I/O失敗をhandlerへ返す。
func (w *responseWriter) FlushError() error {
	if w.bodyBuffer != nil {
		if err := w.commitBodyBuffer(); err != nil {
			w.err = err
			return err
		}
	}
	if err := w.flushHeaders(false); err != nil {
		return err
	}
	if len(w.buffer) > 0 {
		_, w.err = w.stream.Writev(dataPrefix(len(w.buffer)), w.buffer)
		w.buffer = nil
	}
	return w.err
}
func (w *responseWriter) Flush()                             { _ = w.FlushError() }
func (w *responseWriter) SetReadDeadline(t time.Time) error  { return w.stream.SetReadDeadline(t) }
func (w *responseWriter) SetWriteDeadline(t time.Time) error { return w.stream.SetWriteDeadline(t) }
func (w *responseWriter) finish() error {
	if w.status != 0 && bodyAllowed(w.status) && w.request.Method != "HEAD" {
		if value := w.snapshot.Get("Content-Length"); value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n != w.written {
				return http.ErrContentLength
			}
		}
	}
	if !w.sent {
		return w.flushHeaders(true)
	}
	if err := w.FlushError(); err != nil {
		return err
	}
	return w.stream.Close()
}

// endpoint はConnContextにUDPの実アドレスを渡す。I/OはQUIC streamだけで行う。
type endpoint struct{ conn *quicv1.Conn }

func (e *endpoint) LocalAddr() net.Addr              { return e.conn.LocalAddr() }
func (e *endpoint) RemoteAddr() net.Addr             { return e.conn.RemoteAddr() }
func (e *endpoint) Read([]byte) (int, error)         { return 0, errors.ErrUnsupported }
func (e *endpoint) Write([]byte) (int, error)        { return 0, errors.ErrUnsupported }
func (e *endpoint) Close() error                     { return errors.ErrUnsupported }
func (e *endpoint) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (e *endpoint) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (e *endpoint) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

var _ http.ResponseWriter = (*responseWriter)(nil)
var _ http.Flusher = (*responseWriter)(nil)

// dataPrefix は本文の複製を避け、HTTP/3 DATA frameの長さだけを符号化する。
func dataPrefix(length int) []byte { return append([]byte{0}, integer(uint64(length))...) }

// releaseBuffer はQUIC側のコピー完了後に応答の作業bufferを返す。
func (w *responseWriter) releaseBuffer() {
	if w.bodyBuffer != nil {
		w.bodyBuffer.Abort()
		w.bodyBuffer = nil
	}
	if w.bufferOwner != nil {
		clear(w.bufferOwner.data[:])
		responseBuffers.Put(w.bufferOwner)
		w.bufferOwner = nil
		w.buffer = nil
	}
}
