// 管理下の単一mTLS edgeから受けたendpointを、実socket観測と分離して保持する。
package evidence

import (
	"context"
	"net"
	"net/http"
	"oimobbs/internal/domain"
	"strconv"
)

type proxyContextKey struct{}
type proxyObservation struct {
	client, destination Endpoint
	profile             string
	revision            domain.U64
}

// WithAuthenticatedProxy は呼出元がmTLSと許可edgeを認証した要求へ固定endpointを結ぶ。
// TLS/socketを上書きしない。転送headerだけでこの関数を呼んではならない。
func WithAuthenticatedProxy(r *http.Request, client, destination Endpoint, profile string, revision domain.U64) (*http.Request, error) {
	if r == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || !validEndpoint(client) || !validEndpoint(destination) || !validLabel(profile, 128) || revision == 0 {
		return nil, ErrHTTPObservation
	}
	return r.WithContext(context.WithValue(r.Context(), proxyContextKey{}, proxyObservation{client, destination, profile, revision})), nil
}

// ClientRemoteAddr は認証済みedgeの利用者endpoint、直結なら実peerを返す。
func ClientRemoteAddr(r *http.Request) string {
	if p, ok := r.Context().Value(proxyContextKey{}).(proxyObservation); ok {
		return net.JoinHostPort(p.client.IP, strconv.Itoa(int(p.client.Port)))
	}
	return r.RemoteAddr
}

// applyProxyObservation は認証済みedgeの値だけを解決endpointへ結び、実socket観測を維持する。
func applyProxyObservation(r *http.Request, v *HTTPObservation) {
	if p, ok := r.Context().Value(proxyContextKey{}).(proxyObservation); ok {
		v.Resolved, v.ClientSource = p.client, "edge_endpoint_v1"
		v.ProxyProfileID, v.ProxyConfigRevision = &p.profile, &p.revision
		v.VerifiedProxyChain = []Endpoint{v.Peer}
		v.OriginEndpoint = &p.destination
	}
}

// validateProxyObservation は直結の不変条件と単一認証edgeの保存条件を分けて検査する。
func validateProxyObservation(v HTTPObservation) bool {
	if v.ClientSource == "direct" {
		return v.Resolved == v.Peer && v.ProxyProfileID == nil && v.ProxyConfigRevision == nil && v.VerifiedProxyChain != nil && len(v.VerifiedProxyChain) == 0 && v.OriginEndpoint == nil
	}
	return v.ClientSource == "edge_endpoint_v1" && validEndpoint(v.Resolved) && v.ProxyProfileID != nil && validLabel(*v.ProxyProfileID, 128) && v.ProxyConfigRevision != nil && *v.ProxyConfigRevision > 0 && len(v.VerifiedProxyChain) == 1 && v.VerifiedProxyChain[0] == v.Peer && v.OriginEndpoint != nil && validEndpoint(*v.OriginEndpoint) && v.TLSVersion != nil
}
