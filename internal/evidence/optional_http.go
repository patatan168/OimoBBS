// 公開HTTP境界で実socket・投稿裁定・実write結果を非必須キューへ結び、秘密入力を収集しない。
package evidence

import (
	"context"
	"errors"
	"net/http"
	"oimobbs/internal/domain"
	"slices"
	"sync"
	"time"
)

type optionalHTTPContextKey struct{}
type optionalHTTPContext struct {
	mu        sync.Mutex
	observer  *HTTPObserver
	start     time.Time
	request   domain.ID
	board     *domain.ID
	operation *domain.ID
	outcome   string
}

// AnnotateOptionalPosting は実投稿処理の裁定だけを結ぶ。本文や自由文errorは受け取らない。
// 未設置のHTTP境界では何もしない。受理操作IDを拒否/確認の記録に結ぶことはできない。
func AnnotateOptionalPosting(ctx context.Context, board domain.ID, operation *domain.ID, outcome string) error {
	if !slices.Contains([]string{"accepted", "duplicate", "confirmation", "rejected", "uncertain"}, outcome) || operation != nil && (*operation == (domain.ID{}) || outcome != "accepted" && outcome != "duplicate") {
		return ErrHTTPObservation
	}
	state, ok := ctx.Value(optionalHTTPContextKey{}).(*optionalHTTPContext)
	if !ok {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if board != (domain.ID{}) {
		value := board
		state.board = &value
	}
	if operation != nil {
		value := *operation
		state.operation = &value
	}
	state.outcome = outcome
	return nil
}

// WrapOptional は要求全体の外側に設置する。request gate/帯域制限も内側に置けばその拒否を記録できる。
// 実接続のConnContextが無い場合は欠測を集計して通常handlerを通し、架空の接続情報を保存しない。
func (o *HTTPObserver) WrapOptional(next http.Handler, q *OptionalQueue, classify func(*http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		connection, ok := r.Context().Value(connectionContextKey{}).(connectionObservation)
		if !ok || connection.owner != o || connection.err != nil || o == nil || q == nil {
			if q != nil {
				q.invalid()
			}
			next.ServeHTTP(w, r)
			return
		}
		state := &optionalHTTPContext{observer: o, start: start, request: domain.NewID(), outcome: "uncertain"}
		r = r.WithContext(context.WithValue(r.Context(), optionalHTTPContextKey{}, state))
		route := "other"
		if classify != nil {
			route = classify(r)
		}
		observed := &optionalResponseWriter{ResponseWriter: w}
		ua := r.Header.Values("User-Agent")
		var userAgent *HeaderValue
		uaStatus := "captured"
		if len(ua) == 1 && len(ua[0]) <= MaxObservedHeaderBytes {
			value := encodeHeaderValue(ua[0])
			userAgent = &value
		} else if len(ua) > 0 {
			uaStatus = "truncated"
		}
		method, version := r.Method, r.Proto
		var tlsVersion, tlsCipher *uint16
		if r.TLS != nil {
			v, c := r.TLS.Version, r.TLS.CipherSuite
			tlsVersion, tlsCipher = &v, &c
		}
		completed := false
		defer func() {
			finished := time.Now()
			record := OptionalRecord{Schema: "optional-http-v1", ID: domain.NewID(), Site: o.site, Boot: o.boot, Connection: connection.id, Request: state.request, Received: domain.Time(start.UnixNano()), Finished: domain.Time(finished.UnixNano()), Elapsed: domain.U64(finished.Sub(start)), Until: domain.Time(start.Add(OptionalRetention).UnixNano()), Peer: connection.peer, Local: connection.local, Method: method, Route: route, Kind: "access", Outcome: "served", Status: observed.status, Bytes: domain.U64(observed.bytes), WriteFailed: observed.failed || !completed, Canceled: r.Context().Err() != nil, HTTPVersion: version, UAStatus: uaStatus, UserAgent: userAgent, TLSVersion: tlsVersion, TLSCipher: tlsCipher, FinishStage: "handler_return"}
			if !slices.Contains([]string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodPatch, http.MethodConnect, http.MethodTrace}, record.Method) {
				record.Method = "OTHER"
			}
			if record.Status == 0 && completed {
				record.Status = 200
			}
			state.mu.Lock()
			record.Board = state.board
			state.mu.Unlock()
			if route == "legacy_post" || route == "web_post" {
				state.mu.Lock()
				record.Board, record.Operation, record.Outcome = state.board, state.operation, state.outcome
				state.mu.Unlock()
				record.Kind = "attempt"
				q.Enqueue(record)
				record.ID = domain.NewID()
				record.Kind = "response"
				q.Enqueue(record)
				return
			}
			if record.WriteFailed {
				record.Outcome = "interrupted"
			}
			q.Enqueue(record)
		}()
		next.ServeHTTP(observed, r)
		completed = true
	})
}

type optionalResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  uint64
	failed bool
}

// Unwrap はResponseControllerのdeadline/duplex操作を元writerへ通す。
func (w *optionalResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *optionalResponseWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	if w.status == 0 && (status >= 200 || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
}
func (w *optionalResponseWriter) Write(raw []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, e := w.ResponseWriter.Write(raw)
	if n > 0 {
		w.bytes += uint64(n)
	}
	if e != nil || n != len(raw) {
		w.failed = true
	}
	return n, e
}

// FlushError は実flushの失敗を保持し、端末の受信完了として扱わない。
func (w *optionalResponseWriter) FlushError() error {
	e := http.NewResponseController(w.ResponseWriter).Flush()
	if e == nil && w.status == 0 {
		w.status = 200
	}
	if e != nil && !errors.Is(e, http.ErrNotSupported) {
		w.failed = true
	}
	return e
}
func (w *optionalResponseWriter) Flush() { _ = w.FlushError() }

// AnnotateOptionalBoard は実際に解決した板IDだけをHTTP記録へ結ぶ。未設置時は何もしない。
func AnnotateOptionalBoard(ctx context.Context, board domain.ID) {
	if board == (domain.ID{}) {
		return
	}
	state, ok := ctx.Value(optionalHTTPContextKey{}).(*optionalHTTPContext)
	if !ok {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	value := board
	state.board = &value
}
