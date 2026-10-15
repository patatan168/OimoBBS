// 固定のGoogle Public DNS JSON APIでPTR/A/AAAAをHTTPS取得する。
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// GoogleHTTPSResolver はGoogle以外への転送とOS DNSへの照会フォールバックを行わない。
type GoogleHTTPSResolver struct{ client *http.Client }

// NewGoogleHTTPSResolver はTLS検証を有効にし、転送を禁止した有界クライアントを作る。
func NewGoogleHTTPSResolver() *GoogleHTTPSResolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 4
	transport.MaxIdleConnsPerHost = 4
	transport.IdleConnTimeout = 30 * time.Second
	return &GoogleHTTPSResolver{client: &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type dnsAnswer struct {
	Name string
	Type uint16
	Data string
}

// query は回答サイズと件数を制限し、DNSエラーと不正応答を呼出元へ返す。
func (r *GoogleHTTPSResolver) query(ctx context.Context, name string, kind uint16) ([]dnsAnswer, error) {
	q := url.Values{"name": {name}, "type": {fmt.Sprint(kind)}, "edns_client_subnet": {"0.0.0.0/0"}}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://dns.google/resolve?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	res, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("HTTPS DNS response failed")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, errors.New("HTTPS DNS response too large")
	}
	var data struct {
		Status *int
		TC     bool
		Answer []dnsAnswer
	}
	if err = json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	if (data.Status == nil || *data.Status != 0) || data.TC || len(data.Answer) > 64 {
		return nil, errors.New("DNS lookup failed")
	}
	return data.Answer, nil
}

// LookupAddr はIPv4/IPv6の逆引き名を作り、PTR回答だけを返す。
func (r *GoogleHTTPSResolver) LookupAddr(ctx context.Context, raw string) ([]string, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return nil, err
	}
	ip = ip.Unmap()
	var name strings.Builder
	if ip.Is4() {
		a := ip.As4()
		fmt.Fprintf(&name, "%d.%d.%d.%d.in-addr.arpa", a[3], a[2], a[1], a[0])
	} else {
		a := ip.As16()
		const hex = "0123456789abcdef"
		for i := len(a) - 1; i >= 0; i-- {
			name.WriteByte(hex[a[i]&15])
			name.WriteByte('.')
			name.WriteByte(hex[a[i]>>4])
			name.WriteByte('.')
		}
		name.WriteString("ip6.arpa")
	}
	answers, err := r.query(ctx, name.String(), 12)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range answers {
		if a.Type == 12 {
			out = append(out, a.Data)
		}
	}
	return out, nil
}

// LookupNetIP は要求したfamilyのA/AAAAだけを取得する。失敗時に別取得先へ切り替えない。
func (r *GoogleHTTPSResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	kinds := []uint16{1, 28}
	switch network {
	case "ip":
	case "ip4":
		kinds = []uint16{1}
	case "ip6":
		kinds = []uint16{28}
	default:
		return nil, errors.New("unsupported DNS network")
	}
	var out []netip.Addr
	for _, kind := range kinds {
		answers, err := r.query(ctx, host, kind)
		if err != nil {
			return nil, err
		}
		for _, a := range answers {
			if a.Type != kind {
				continue
			}
			ip, err := netip.ParseAddr(a.Data)
			if err != nil || kind == 1 && !ip.Is4() || kind == 28 && (!ip.Is6() || ip.Is4In6()) {
				return nil, errors.New("invalid DNS address")
			}
			out = append(out, ip)
		}
	}
	return out, nil
}

// CloseIdleConnections は方式変更・停止時に未使用のHTTPS接続を回収する。
func (r *GoogleHTTPSResolver) CloseIdleConnections() { r.client.CloseIdleConnections() }
