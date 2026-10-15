// 直結HTTPの観測成分を収集する。投稿内容・認可・確定結果は別の保存項目として結合する。
package evidence

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"oimobbs/internal/domain"
	"sync"
	"time"
)

const MaxObservedBodyBytes = 64 << 10

var ErrHTTPObservation = errors.New("invalid or incomplete HTTP observation")
var ErrObservedBodyTooLarge = errors.New("posting body exceeds observation limit")

// Endpoint は観測または認証edgeが申告したIPとport。出所は観測型で区別し、公開DTOへ含めない。
type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// MissingField はnull項目の欠測理由。値を推定して埋めない。
type MissingField struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// HeaderValue はHTTPパーサ値の元byteと、UTF-8の表示用文字列を分離する。
type HeaderValue struct {
	Base64  string `json:"base64"`
	Display string `json:"display"`
}

// ObservedHeader は許可ヘッダだけを持つ。Originはorigin_onlyとして秘密を落とす。
type ObservedHeader struct {
	Name           string        `json:"name"`
	Representation string        `json:"representation"`
	Values         []HeaderValue `json:"values"`
}

// HTTPObservation はevidence-v1の接続・要求・受付時刻に対応する成分。
// これだけでは投稿内容・principal・確定結果を含む完全なevidenceではない。
type HTTPObservation struct {
	Schema              string           `json:"schema"`
	SiteID              domain.ID        `json:"site_id"`
	InstanceID          domain.ID        `json:"site_instance_id"`
	BoardID             domain.ID        `json:"board_id"`
	BootID              domain.ID        `json:"process_boot_id"`
	ConnectionID        domain.ID        `json:"connection_id"`
	RequestID           domain.ID        `json:"request_id"`
	Received            domain.Time      `json:"received_at_ns"`
	BodyCompleted       domain.Time      `json:"body_completed_at_ns"`
	MonotonicElapsed    domain.U64       `json:"monotonic_elapsed_ns"`
	ClockStatus         string           `json:"clock_status"`
	ClockSource         string           `json:"clock_source"`
	ClockOffsetMS       *int64           `json:"clock_offset_ms"`
	ClockObserved       *domain.Time     `json:"clock_observed_at_ns"`
	Peer                Endpoint         `json:"peer"`
	Local               Endpoint         `json:"local"`
	Transport           string           `json:"transport"`
	HTTPVersion         string           `json:"http_version"`
	TLSVersion          *uint16          `json:"tls_version"`
	TLSCipherSuite      *uint16          `json:"tls_cipher_suite"`
	SNI                 *string          `json:"sni"`
	Resolved            Endpoint         `json:"resolved"`
	ClientSource        string           `json:"client_source"`
	ProxyProfileID      *string          `json:"proxy_profile_id"`
	ProxyConfigRevision *domain.U64      `json:"proxy_config_revision"`
	VerifiedProxyChain  []Endpoint       `json:"verified_proxy_chain"`
	OriginEndpoint      *Endpoint        `json:"origin_endpoint"`
	Method              string           `json:"method"`
	Route               string           `json:"route"`
	CanonicalHost       string           `json:"canonical_host"`
	DeclaredCharset     *string          `json:"declared_charset"`
	BodyBytes           domain.U64       `json:"body_bytes"`
	SelectedHeaders     []ObservedHeader `json:"selected_headers"`
	ReportedHeaders     []ObservedHeader `json:"reported_headers"`
	HeaderCaptureStatus string           `json:"header_capture_status"`
	ParsedHeaderBytes   domain.U64       `json:"parsed_header_bytes"`
	MissingFields       []MissingField   `json:"missing_fields"`
	ServerBuildID       string           `json:"server_build_id"`
}

// HTTPObserver は実socketを固定する観測器。認証edgeの値は専用contextから別項目へ結ぶ。
type HTTPObserver struct {
	site, instance, boot domain.ID
	build                string
}
type connectionObservation struct {
	owner       *HTTPObserver
	id          domain.ID
	peer, local Endpoint
	err         error
}
type connectionContextKey struct{}

// NewHTTPObserver は設定済みの永続site/instance IDを受け取り、boot IDを新規生成する。
func NewHTTPObserver(site, instance domain.ID, build string) (*HTTPObserver, error) {
	if site == (domain.ID{}) || instance == (domain.ID{}) || !validLabel(build, 128) {
		return nil, ErrHTTPObservation
	}
	return &HTTPObserver{site, instance, domain.NewID(), build}, nil
}

// ConnContext は実接続からendpointを固定する。既存のConnContextがある場合は呼出元で合成する。
func (o *HTTPObserver) ConnContext(ctx context.Context, conn net.Conn) context.Context {
	c := connectionObservation{owner: o, id: domain.NewID()}
	if conn == nil {
		c.err = ErrHTTPObservation
	} else {
		c.peer, c.err = socketEndpoint(conn.RemoteAddr())
		if c.err == nil {
			c.local, c.err = socketEndpoint(conn.LocalAddr())
		}
	}
	return context.WithValue(ctx, connectionContextKey{}, c)
}

// HTTPCapture は一要求の観測状態。Beginで設置したBodyをEOFまで読み、Finishを一度呼ぶ。
type HTTPCapture struct {
	mu                         sync.Mutex
	value                      HTTPObservation
	start                      time.Time
	complete, failed, finished bool
}

// Begin はhandler受付時に呼ぶ。要求URL・Cookie・本文は保持せず、Bodyへ計数器を設置する。
// route/hostは照合済みルーター設定値を渡す。転送ヘッダは申告欄へ保存するだけで信頼しない。
func (o *HTTPObserver) Begin(r *http.Request, board domain.ID, route, host string) (*HTTPCapture, error) {
	if board == (domain.ID{}) {
		return nil, ErrHTTPObservation
	}
	return o.begin(r, board, route, host)
}

// BeginLegacyRouting は本文中のbbs解決前に直結観測を開始する。FinishForBoardで板を確定するまで保存不能。
func (o *HTTPObserver) BeginLegacyRouting(r *http.Request, host string) (*HTTPCapture, error) {
	return o.begin(r, domain.ID{}, "bbs_post", host)
}
func (o *HTTPObserver) begin(r *http.Request, board domain.ID, route, host string) (*HTTPCapture, error) {
	start := time.Now()
	if r == nil || o == nil {
		return nil, ErrHTTPObservation
	}
	c, ok := r.Context().Value(connectionContextKey{}).(connectionObservation)
	if !ok || c.owner != o || c.err != nil || r.Method != "POST" || !validRoute(route) || !validAuthority(host) {
		return nil, ErrHTTPObservation
	}
	headers, reported, size, e := captureHeaders(r.Header, r.Host)
	if e != nil {
		return nil, e
	}
	charset, e := declaredCharset(headers)
	if e != nil {
		return nil, e
	}
	requestID := domain.NewID()
	if state, ok := r.Context().Value(optionalHTTPContextKey{}).(*optionalHTTPContext); ok && state.observer == o {
		start, requestID = state.start, state.request
	}
	v := HTTPObservation{Schema: "http-observation-v1", SiteID: o.site, InstanceID: o.instance, BoardID: board, BootID: o.boot, ConnectionID: c.id, RequestID: requestID, Received: domain.Time(start.UnixNano()), ClockStatus: "unknown", ClockSource: "unconfigured", Peer: c.peer, Local: c.local, Transport: "tcp", HTTPVersion: r.Proto, Resolved: c.peer, ClientSource: "direct", VerifiedProxyChain: []Endpoint{}, Method: r.Method, Route: route, CanonicalHost: host, DeclaredCharset: charset, SelectedHeaders: headers, ReportedHeaders: reported, HeaderCaptureStatus: "captured", ParsedHeaderBytes: domain.U64(size), ServerBuildID: o.build}
	if r.TLS != nil {
		version, cipher := r.TLS.Version, r.TLS.CipherSuite
		v.TLSVersion = &version
		v.TLSCipherSuite = &cipher
		if r.TLS.ServerName != "" {
			sni := r.TLS.ServerName
			v.SNI = &sni
		}
	}
	applyProxyObservation(r, &v)
	v.MissingFields = observationMissing(v)
	if e = validateConnectionObservation(v); e != nil {
		return nil, e
	}
	capture := &HTTPCapture{value: v, start: start}
	if r.Body == nil || r.Body == http.NoBody {
		capture.complete = true
		capture.value.BodyCompleted = v.Received
	} else {
		r.Body = &observedBody{source: r.Body, capture: capture}
	}
	return capture, nil
}

// FinishForBoard は読了したlegacyフォームの解決済み板を一度だけ結び付けて確定する。
// 既に板へ束縛したcaptureの付替え、ゼロID、読残しは拒否する。
func (c *HTTPCapture) FinishForBoard(board domain.ID) (HTTPObservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if board == (domain.ID{}) || c.value.BoardID != (domain.ID{}) || c.value.Route != "bbs_post" || !c.complete || c.failed || c.finished {
		return HTTPObservation{}, ErrHTTPObservation
	}
	c.value.BoardID = board
	return c.finishLocked()
}

// Finish は本文読了後に計数済み観測値を返す。読残し・読取失敗・二重確定は拒否する。
func (c *HTTPCapture) Finish() (HTTPObservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.finishLocked()
}
func (c *HTTPCapture) finishLocked() (HTTPObservation, error) {
	if !c.complete || c.failed || c.finished {
		return HTTPObservation{}, ErrHTTPObservation
	}
	if e := validateObservation(c.value); e != nil {
		return HTTPObservation{}, e
	}
	c.finished = true
	return c.value, nil
}

type observedBody struct {
	source  io.ReadCloser
	capture *HTTPCapture
}

func (b *observedBody) Read(p []byte) (int, error) {
	c := b.capture
	c.mu.Lock()
	remaining := int64(MaxObservedBodyBytes) - int64(c.value.BodyBytes)
	failed := c.failed
	c.mu.Unlock()
	if failed || remaining < 0 {
		return 0, ErrObservedBodyTooLarge
	}
	if int64(len(p)) > remaining+1 {
		p = p[:remaining+1]
	}
	n, e := b.source.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value.BodyBytes += domain.U64(n)
	if c.value.BodyBytes > MaxObservedBodyBytes {
		c.failed = true
		return n, ErrObservedBodyTooLarge
	}
	if e == io.EOF && !c.complete {
		end := time.Now()
		c.complete = true
		c.value.BodyCompleted = domain.Time(end.UnixNano())
		c.value.MonotonicElapsed = domain.U64(end.Sub(c.start).Nanoseconds())
		if c.value.BodyCompleted < c.value.Received {
			c.value.ClockStatus = "degraded"
		}
	} else if e != nil && e != io.EOF {
		c.failed = true
	}
	return n, e
}
func (b *observedBody) Close() error {
	e := b.source.Close()
	b.capture.mu.Lock()
	defer b.capture.mu.Unlock()
	if !b.capture.complete || e != nil {
		b.capture.failed = true
	}
	return e
}
