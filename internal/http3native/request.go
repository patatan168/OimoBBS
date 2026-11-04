// HTTP/3のfield sectionをnet/httpへ変換し、pseudo-headerと本文長の契約を検証する。
package http3native

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
	"oimobbs/internal/quicv1"
)

func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }
func (c *connection) request(s *quicv1.Stream) {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	stopCancel := context.AfterFunc(s.Context(), cancel)
	defer stopCancel()
	defer func() {
		s.CancelRead(errCancelled)
		if recovered := recover(); recovered != nil {
			s.CancelWrite(errInternal)
		}
	}()
	h := c.server.HTTP
	deadline := h.ReadHeaderTimeout
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	_ = s.SetReadDeadline(time.Now().Add(deadline))
	if h.WriteTimeout > 0 {
		_ = s.SetWriteDeadline(time.Now().Add(h.WriteTimeout))
	}
	fields, err := c.requestHeaders(ctx, s)
	if err != nil {
		var ce *connectionError
		if errors.As(err, &ce) {
			c.fail(ce.code)
		} else {
			s.CancelWrite(errIncomplete)
		}
		return
	}
	limit := h.MaxHeaderBytes
	if limit <= 0 || limit > 16<<10 {
		limit = 16 << 10
	}
	total := 0
	for _, f := range fields {
		total += 32 + len(f.Name) + len(f.Value)
	}
	if total > limit {
		s.CancelWrite(errMessage)
		return
	}
	r, err := requestFields(fields, ctx)
	if err != nil {
		s.CancelWrite(errMessage)
		return
	}
	c.grantControl()
	r.Proto = "HTTP/3.0"
	r.ProtoMajor = 3
	r.ProtoMinor = 0
	r.RemoteAddr = c.remoteAddr
	r.TLS = &c.tlsState
	body := &requestBody{stream: s, qpack: c.qpack, ctx: ctx, connection: c, remaining: r.ContentLength, trailers: r.Trailer}
	r.Body = body
	if h.ReadTimeout > 0 {
		_ = s.SetReadDeadline(time.Now().Add(h.ReadTimeout))
	} else {
		_ = s.SetReadDeadline(time.Time{})
	}
	w := &responseWriter{stream: s, qpack: c.qpack, connection: c, request: r, header: make(http.Header)}
	defer w.releaseBuffer()
	handler := h.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}
	handler.ServeHTTP(w, r)
	if err = w.finish(); err != nil {
		s.CancelWrite(errInternal)
	}
}
func (c *connection) requestHeaders(ctx context.Context, s *quicv1.Stream) ([]Field, error) {
	skipped := uint64(0)
	for {
		kind, n, err := readFrame(s)
		if err != nil {
			return nil, err
		}
		if kind == 1 {
			if n > 16<<10 {
				return nil, &connectionError{0x107}
			}
			data, err := bounded(s, n, 16<<10)
			if err != nil {
				return nil, err
			}
			f, err := c.qpack.decode(ctx, s.ID(), data, s.ReadDeadline())
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, err
				}
				return nil, &connectionError{errQPACK}
			}
			return f, nil
		}
		if kind == 0 || forbiddenRequestFrame(kind) {
			return nil, &connectionError{errFrameUnexpected}
		}
		if err := chargeFraming(&skipped, n); err != nil {
			return nil, err
		}
		if _, err = io.CopyN(io.Discard, s, int64(n)); err != nil {
			return nil, err
		}
	}
}
func requestFields(fields []Field, ctx context.Context) (*http.Request, error) {
	r := (&http.Request{Header: make(http.Header), Trailer: make(http.Header), ContentLength: -1}).WithContext(ctx)
	pseudo := map[string]string{}
	regular := false
	var length string
	lengthSet := false
	hostSet := false
	for _, f := range fields {
		if strings.ToLower(f.Name) != f.Name || !validFieldValue(f.Value) {
			return nil, errors.New("invalid field")
		}
		if strings.HasPrefix(f.Name, ":") {
			if regular || pseudo[f.Name] != "" || f.Value == "" {
				return nil, errors.New("pseudo field order/duplicate")
			}
			switch f.Name {
			case ":method", ":scheme", ":path", ":authority":
				pseudo[f.Name] = f.Value
			default:
				return nil, errors.New("unknown pseudo field")
			}
			continue
		}
		regular = true
		if !httpguts.ValidHeaderFieldName(f.Name) {
			return nil, errors.New("invalid field name")
		}
		switch f.Name {
		case "connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding":
			return nil, errors.New("connection specific field")
		case "te":
			if f.Value != "trailers" {
				return nil, errors.New("invalid TE")
			}
		case "content-length":
			if lengthSet && length != f.Value {
				return nil, errors.New("conflicting content length")
			}
			length = f.Value
			lengthSet = true
		case "host":
			if hostSet {
				return nil, errors.New("duplicate host")
			}
			hostSet = true
			r.Host = f.Value
		}
		if f.Name == "cookie" && r.Header.Get("Cookie") != "" {
			r.Header.Set("Cookie", r.Header.Get("Cookie")+"; "+f.Value)
		} else {
			r.Header.Add(f.Name, f.Value)
		}
	}
	method := pseudo[":method"]
	if !httpguts.ValidHeaderFieldName(method) {
		return nil, errors.New("invalid method")
	}
	if method == "CONNECT" {
		return nil, errors.New("CONNECT unsupported")
	}
	if pseudo[":scheme"] != "https" || pseudo[":path"] == "" {
		return nil, errors.New("invalid scheme/path")
	}
	if hostSet && pseudo[":authority"] != "" && r.Host != pseudo[":authority"] {
		return nil, errors.New("host mismatch")
	}
	if pseudo[":authority"] != "" {
		r.Host = pseudo[":authority"]
	}
	if !httpguts.ValidHostHeader(r.Host) || r.Host == "" {
		return nil, errors.New("invalid host")
	}
	target := pseudo[":path"]
	if !strings.HasPrefix(target, "/") && !(method == "OPTIONS" && target == "*") {
		return nil, errors.New("invalid request target")
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Fragment != "" {
		return nil, errors.New("invalid request URI")
	}
	r.URL = u
	r.Method = method
	r.RequestURI = target
	if lengthSet {
		if length == "" {
			return nil, errors.New("empty content length")
		}
		for _, b := range length {
			if b < '0' || b > '9' {
				return nil, errors.New("invalid content length")
			}
		}
		n, err := strconv.ParseInt(length, 10, 64)
		if err != nil {
			return nil, err
		}
		r.ContentLength = n
	}
	return r, nil
}

type requestBody struct {
	stream             *quicv1.Stream
	qpack              *QPACK
	ctx                context.Context
	connection         *connection
	readErr            error
	remaining          int64
	frameRemaining     uint64
	trailers           http.Header
	ended, gotTrailers bool
	framing            uint64
}

// Read は最初の本文エラーで受信を停止し、再読取りにも同じエラーを返す。
func (b *requestBody) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if b.readErr != nil {
		return 0, b.readErr
	}
	n, err := b.read(data)
	if err != nil && err != io.EOF {
		b.readErr = err
		b.ended = true
		code := uint64(errMessage)
		var ce *connectionError
		if errors.As(err, &ce) {
			code = ce.code
			// 本文の処理量超過はstream内に留め、既存どおり400を返せるようにする。
			if b.connection != nil && code != errExcessive {
				b.connection.fail(code)
			}
		}
		b.stream.CancelRead(code)
	}
	return n, err
}

// read は最初の失敗までを解析する。Readが失敗を保持し、再読取りで解析を再開させない。
func (b *requestBody) read(data []byte) (int, error) {
	if b.ended {
		return 0, io.EOF
	}
	for b.frameRemaining == 0 {
		kind, n, err := readFrame(b.stream)
		if err != nil {
			b.ended = true
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				return 0, err
			}
			if err == io.EOF && b.remaining <= 0 {
				return 0, io.EOF
			}
			b.stream.CancelWrite(errMessage)
			return 0, io.ErrUnexpectedEOF
		}
		payload := n
		if kind == 0 {
			payload = 0
		}
		if err := chargeFraming(&b.framing, payload); err != nil {
			b.stream.CancelRead(errExcessive)
			return 0, err
		}
		switch kind {
		case 0:
			if b.gotTrailers {
				return 0, &connectionError{errFrameUnexpected}
			}
			if b.remaining >= 0 && n > uint64(b.remaining) {
				b.stream.CancelWrite(errMessage)
				return 0, errors.New("body length mismatch")
			}
			b.frameRemaining = n
		case 1:
			if b.gotTrailers {
				return 0, &connectionError{errFrameUnexpected}
			}
			block, err := bounded(b.stream, n, 16<<10)
			if err != nil {
				return 0, err
			}
			fields, err := b.qpack.decode(b.ctx, b.stream.ID(), block, b.stream.ReadDeadline())
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return 0, err
				}
				return 0, &connectionError{errQPACK}
			}
			for _, f := range fields {
				if !httpguts.ValidHeaderFieldName(f.Name) || strings.ToLower(f.Name) != f.Name || !validFieldValue(f.Value) || !httpguts.ValidTrailerHeader(f.Name) || f.Name == "upgrade" {
					return 0, errors.New("invalid trailer")
				}
			}
			for _, f := range fields {
				b.trailers.Add(f.Name, f.Value)
			}
			b.gotTrailers = true
		default:
			if forbiddenRequestFrame(kind) {
				return 0, &connectionError{errFrameUnexpected}
			}
			if _, err = io.CopyN(io.Discard, b.stream, int64(n)); err != nil {
				return 0, err
			}
		}
	}
	n, err := b.stream.Read(data[:min(uint64(len(data)), b.frameRemaining)])
	b.frameRemaining -= uint64(n)
	if b.remaining >= 0 {
		b.remaining -= int64(n)
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
func (b *requestBody) Close() error { b.stream.CancelRead(errCancelled); return nil }
