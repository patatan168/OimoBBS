// HTTPのヘッダ・HEAD/304/エラー・本文を共通送信予算へ接続する。
package delivery

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// Response はヘッダを一度、本文を16KiBずつ予約してから下位writerへ送る。
// WriteCheckedの検査は帯域待ちの後・socket書込み直前に行う。
type Response struct {
	http.ResponseWriter
	scheduler       *Scheduler
	ip              netip.Addr
	ctx             context.Context
	started         bool
	terminal        error
	failureResponse bool
}

// Wrap は全応答を帯域枠へ通す。不正接続元は本文なしで応答を中断する。
func (s *Scheduler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		ip, err := netip.ParseAddr(host)
		if e != nil || err != nil || ip.Zone() != "" {
			panic(http.ErrAbortHandler)
		}
		out := &Response{ResponseWriter: w, scheduler: s, ip: ip.Unmap(), ctx: r.Context()}
		next.ServeHTTP(out, r)
		if out.terminal != nil && !out.failureResponse {
			panic(http.ErrAbortHandler)
		}
		if !out.started && out.terminal == nil {
			out.WriteHeader(200)
		}
	})
}

// Unwrap はdeadline等のResponseController操作を実socketへ渡す。
func (w *Response) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *Response) reserve(size int) (*Permit, error) {
	if w.terminal != nil {
		return nil, w.terminal
	}
	ctx, cancel := context.WithTimeout(w.ctx, 250*time.Millisecond)
	defer cancel()
	return w.scheduler.reserveHTTP(ctx, w.ip, size)
}

// headerBytes は標準HTTPの自動ヘッダ分も保守的に加え、HEAD/304も課金する。
func (w *Response) headerBytes(status int) int {
	size := 256 + len(strconv.Itoa(status)) + len(http.StatusText(status))
	for k, values := range w.Header() {
		for _, v := range values {
			size += len(k) + len(v) + 4
		}
	}
	return size
}

// WriteHeaderChecked は推定ヘッダ量の予約後、任意の公開リース検査を行って確定する。
func (w *Response) WriteHeaderChecked(status int, check func() error) error {
	if w.started {
		return nil
	}
	// 1xxの多段送信/upgradeは本ルーターの契約外。帯域を迂回させない。
	if status < 200 || status > 599 {
		return errors.New("unsupported response status")
	}
	size := w.headerBytes(status)
	if size > Chunk {
		w.abort(errors.New("response headers exceed 16KiB"))
	}
	permit, e := w.reserve(size)
	if e != nil {
		w.fail(e)
		return e
	}
	defer permit.Release()
	if check != nil {
		if e = check(); e != nil {
			return e
		}
	}
	if e = w.ctx.Err(); e != nil {
		w.abort(e)
	}
	w.ResponseWriter.WriteHeader(status)
	w.started = true
	return nil
}

// WriteHeader はエラー・リダイレクトを含め全ヘッダへ帯域予約を適用する。
func (w *Response) WriteHeader(status int) {
	if e := w.WriteHeaderChecked(status, nil); e != nil && !w.started {
		w.abort(e)
	}
}

// WriteChecked は送信片ごとに予約し、待機中に失効した本文を送らない。
func (w *Response) WriteChecked(body []byte, check func() error) (int, error) {
	if w.terminal != nil {
		return 0, w.terminal
	}
	if !w.started {
		if w.Header().Get("Content-Type") == "" && len(body) > 0 {
			w.Header().Set("Content-Type", http.DetectContentType(body))
		}
		if e := w.WriteHeaderChecked(200, check); e != nil {
			return 0, e
		}
	}
	total := 0
	for len(body) > 0 {
		size := min(w.scheduler.bodyChunk(), len(body))
		permit, e := w.reserve(size)
		if e != nil {
			w.fail(e)
			return total, e
		}
		if check != nil {
			e = check()
		}
		if e == nil {
			e = w.ctx.Err()
		}
		if e != nil {
			permit.Release()
			w.terminal = e
			return total, e
		}
		n, e := w.ResponseWriter.Write(body[:size])
		permit.Release()
		total += n
		if e != nil {
			w.terminal = e
			return total, e
		}
		if n != size {
			w.terminal = io.ErrShortWrite
			return total, io.ErrShortWrite
		}
		body = body[size:]
	}
	return total, nil
}

func (w *Response) Write(body []byte) (int, error) { return w.WriteChecked(body, nil) }

// FlushError は暗黙ヘッダにも予約し、失敗を下位socketのflushへ進めない。
func (w *Response) FlushError() error {
	if w.terminal != nil {
		return w.terminal
	}
	if !w.started {
		if e := w.WriteHeaderChecked(200, nil); e != nil {
			return e
		}
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// fail は開始前なら小さい503も予約し、送信余力がなければ無応答で中断する。
func (w *Response) fail(cause error) {
	if w.started {
		w.abort(cause)
	}
	for k := range w.Header() {
		w.Header().Del(k)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Retry-After", "1")
	body := []byte("現在混雑しています。\n")
	permit, e := w.reserve(w.headerBytes(503) + len(body))
	if e != nil {
		w.abort(cause)
	}
	defer permit.Release()
	w.ResponseWriter.WriteHeader(503)
	w.started = true
	w.failureResponse = true
	_, _ = w.ResponseWriter.Write(body)
	w.terminal = cause
}

// abort はHTTP/1接続またはHTTP/2 streamを中断し、無制限エラー送信を避ける。
func (w *Response) abort(cause error) { w.terminal = cause; panic(http.ErrAbortHandler) }
