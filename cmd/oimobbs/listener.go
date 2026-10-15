// 公開の接続枠をTLS前に適用し、認証edgeの集約接続とは区別する。
package main

import (
	"errors"
	"net"
	"net/netip"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/delivery"
)

// limitPublicListener は直結では接続元64枠、認証edgeでは既存の全体枠を使う。
// edgeの利用者別制限はmTLS検証後に確定したendpointへ要求層で適用する。
func limitPublicListener(listener net.Listener, cfg bootstrap.Config) (net.Listener, error) {
	if cfg.Edge != nil {
		prefixes := make([]netip.Prefix, 0, len(cfg.TrustedProxies))
		for _, value := range cfg.TrustedProxies {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Zone() != "" {
				return nil, errors.New("invalid trusted edge source")
			}
			prefixes = append(prefixes, prefix)
		}
		if listener == nil || len(prefixes) == 0 {
			return nil, errors.New("trusted edge sources required")
		}
		return delivery.LimitListener(&edgePeerListener{Listener: listener, prefixes: prefixes}, 4096)
	}
	return delivery.LimitListenerBySource(listener, 4096, 64)
}

type edgePeerListener struct {
	net.Listener
	prefixes []netip.Prefix
}

// Accept は信頼した実TCP peerだけをTLSへ渡す。mTLSと固定leaf検査も別途必須。
// 許可外peerは全体接続枠を消費させず、認証edgeの集約peerには利用者枠を適用しない。
func (l *edgePeerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.allowed(conn.RemoteAddr()) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// allowed は既存の認証後CIDR照合と同じunmapped IPを使い、転送申告を参照しない。
func (l *edgePeerListener) allowed(address net.Addr) bool {
	if address == nil {
		return false
	}
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil || endpoint.Addr().Zone() != "" {
		return false
	}
	for _, prefix := range l.prefixes {
		if prefix.Contains(endpoint.Addr().Unmap()) {
			return true
		}
	}
	return false
}
