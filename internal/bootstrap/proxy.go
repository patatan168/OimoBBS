// 単一の認証TLS終端に限り、上書き済みの利用者endpointを受理する。
package bootstrap

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// EdgeConfig は単一edgeのmTLS認証と変更revisionを固定する起動設定。
type EdgeConfig struct {
	ID                string `json:"id"`
	Revision          uint64 `json:"revision"`
	ClientCA          string `json:"client_ca_file"`
	CertificateSHA256 string `json:"client_certificate_sha256"`
}

// validateEdge は証明書固定と明示CIDRを必須にし、直結との設定混在を拒否する。
func (c Config) validateEdge() error {
	if c.TrustedProxies == nil {
		return errors.New("trusted_proxies must be an array")
	}
	if c.Edge == nil {
		if len(c.TrustedProxies) != 0 {
			return errors.New("trusted proxies require an authenticated edge")
		}
		return nil
	}
	if len(c.TrustedProxies) == 0 || len(c.TrustedProxies) > 16 || c.Edge.ID == "" || len(c.Edge.ID) > 32 || c.Edge.Revision == 0 || c.Edge.ClientCA == "" {
		return errors.New("invalid edge configuration")
	}
	for _, ch := range c.Edge.ID {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return errors.New("invalid edge ID")
		}
	}
	hash, e := hex.DecodeString(c.Edge.CertificateSHA256)
	if e != nil || len(hash) != 32 || hex.EncodeToString(hash) != c.Edge.CertificateSHA256 {
		return errors.New("canonical client certificate SHA256 required")
	}
	for _, value := range c.TrustedProxies {
		p, e := netip.ParsePrefix(value)
		if e != nil || p.Addr().Zone() != "" || p != p.Masked() || p.Bits() == 0 {
			return errors.New("explicit canonical trusted proxy CIDR required")
		}
	}
	return nil
}

// edgeTLS は独立CAと通常のTLS検証に加え、許可したleaf証明書のhashを検査する。
func (c Config) edgeTLS(cfg *tls.Config) error {
	if c.Edge == nil {
		return nil
	}
	pem, e := os.ReadFile(c.Edge.ClientCA)
	if e != nil {
		return e
	}
	if len(pem) > 64<<10 {
		return errors.New("edge CA exceeds limit")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid edge client CA")
	}
	cfg.ClientAuth, cfg.ClientCAs = tls.RequireAndVerifyClientCert, roots
	expected := c.Edge.CertificateSHA256
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("edge client certificate required")
		}
		digest := sha256.Sum256(state.PeerCertificates[0].Raw)
		if hex.EncodeToString(digest[:]) != expected {
			return errors.New("edge client certificate is not allowed")
		}
		return nil
	}
	return nil
}

// edgeHandler は認証済み単一edgeの固定headerだけを利用する。欠落/重複/矛盾は本文を読む前に拒否する。
func (c Config) edgeHandler(next http.Handler) http.Handler {
	if c.Edge == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, e := c.authenticatedEdgeRequest(r)
		if e != nil {
			postingHeaders(w)
			http.Error(w, "接続元を確認してください。", http.StatusBadRequest)
			return
		}
		// 既存の送信/要求枠にも利用者IPを渡す。実peer/localはConnContextで固定済み。
		request.RemoteAddr = evidence.ClientRemoteAddr(request)
		next.ServeHTTP(w, request)
	})
}

// authenticatedEdgeRequest は実peerとmTLSを照合してから、単値の申告endpointへ認証を結ぶ。
func (c Config) authenticatedEdgeRequest(r *http.Request) (*http.Request, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrPostingRequest
	}
	digest := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	if hex.EncodeToString(digest[:]) != c.Edge.CertificateSHA256 {
		return nil, ErrPostingRequest
	}
	peer, e := netip.ParseAddrPort(r.RemoteAddr)
	if e != nil || !c.trustedEdge(peer.Addr().Unmap()) {
		return nil, ErrPostingRequest
	}
	client, e := edgeEndpoint(r.Header, "X-Oimo-Client-IP", "X-Oimo-Client-Port")
	if e != nil {
		return nil, e
	}
	destination, e := edgeEndpoint(r.Header, "X-Oimo-Dest-IP", "X-Oimo-Dest-Port")
	if e != nil {
		return nil, e
	}
	if _, present, e := singleRequestHeader(r.Header, "Forwarded"); e != nil || present {
		return nil, ErrPostingRequest
	}
	if xff, present, e := singleRequestHeader(r.Header, "X-Forwarded-For"); e != nil || present && xff != client.IP {
		return nil, ErrPostingRequest
	}
	requestID, present, e := singleRequestHeader(r.Header, "X-Oimo-Edge-Request")
	if e != nil || !present || len(requestID) > 128 || strings.ContainsAny(requestID, " \t\r\n") {
		return nil, ErrPostingRequest
	}
	timestamp, present, e := singleRequestHeader(r.Header, "X-Oimo-Edge-Time")
	n, parseErr := strconv.ParseInt(timestamp, 10, 64)
	if e != nil || !present || parseErr != nil || n <= 0 || strconv.FormatInt(n, 10) != timestamp {
		return nil, ErrPostingRequest
	}
	profile := "edge:" + c.Edge.ID + ":" + c.Edge.CertificateSHA256
	return evidence.WithAuthenticatedProxy(r, client, destination, profile, domain.U64(c.Edge.Revision))
}

func (c Config) trustedEdge(ip netip.Addr) bool {
	for _, raw := range c.TrustedProxies {
		p, e := netip.ParsePrefix(raw)
		if e == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

// edgeEndpoint は正規IP literalと非ゼロportを曖昧な補完なしで読む。
func edgeEndpoint(header http.Header, ipName, portName string) (evidence.Endpoint, error) {
	raw, present, e := singleRequestHeader(header, ipName)
	ip, parseErr := netip.ParseAddr(raw)
	if e != nil || !present || parseErr != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.Unmap().String() != raw {
		return evidence.Endpoint{}, ErrPostingRequest
	}
	raw, present, e = singleRequestHeader(header, portName)
	port, parseErr := validPort(raw)
	if e != nil || !present || parseErr != nil {
		return evidence.Endpoint{}, ErrPostingRequest
	}
	return evidence.Endpoint{IP: ip.String(), Port: port}, nil
}
