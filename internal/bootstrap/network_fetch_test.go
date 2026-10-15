// 外部データの版・CSV・衝突・有界取得と公開HTTPS接続条件を検査する。
package bootstrap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type networkTestTransport func(*http.Request) (*http.Response, error)

func (f networkTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// networkTestClient は実TLS試験サーバーへ接続を差し替え、運用のHTTPS URL検査は維持する。
func networkTestClient(server *httptest.Server) *http.Client {
	client := server.Client()
	transport := client.Transport
	target, _ := url.Parse(server.URL)
	client.Transport = networkTestTransport(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		u := *req.URL
		u.Scheme, u.Host = target.Scheme, target.Host
		clone.URL = &u
		return transport.RoundTrip(clone)
	})
	return client
}

func TestNetworkFeedValidation(t *testing.T) {
	source := NetworkSource{Name: "test", Type: "asn", ASN: 9605, Kind: "mobile", Label: "携帯", Suffix: "d"}
	valid := `{"asn":9605,"metadata":{"description":"fixture"},"prefixes":{"ipv4":["192.0.2.0/24"],"ipv6":["2001:db8::/32"]}}`
	rows, e := parseASNNetworks([]byte(valid), source)
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	for _, raw := range []string{strings.Replace(valid, "9605", "9606", 1), strings.Replace(valid, "192.0.2.0/24", "192.0.2.1/24", 1), strings.Replace(valid, `"ipv6":["2001:db8::/32"]`, `"ipv6":null`, 1), `{"asn":9605,"asn":9605,"prefixes":{"ipv4":[],"ipv6":[]}}`} {
		if _, e = parseASNNetworks([]byte(raw), source); e == nil {
			t.Fatal(raw)
		}
	}
	csvRows, e := parseNetworkCSV([]byte("network,connection_type\n192.0.2.0/24,Cellular\n2001:db8::/32,Cable/DSL\n"))
	if e != nil || len(csvRows) != 2 || csvRows[0].Kind != "mobile" || csvRows[1].Kind != "fixed" {
		t.Fatal(csvRows, e)
	}
	for _, raw := range []string{"network,connection_type\n192.0.2.0/24,Unrecognized\n", "cidr,kind,label,suffix\n192.0.2.0/24,mobile,携帯,S\n192.0.2.0/24,mvno,MVNO,M\n", "cidr,kind,label,suffix\n192.0.2.1/24,mobile,携帯,S\n"} {
		if _, e = parseNetworkCSV([]byte(raw)); e == nil {
			t.Fatal(raw)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "9606") {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(valid))
	}))
	defer server.Close()
	other := source
	other.ASN = 9606
	other.Name = "other"
	if _, e = fetchNetworkRows(context.Background(), networkTestClient(server), []NetworkSource{source, other}); e == nil {
		t.Fatal("partial successful table accepted")
	}
}

func TestNetworkHTTPSBoundary(t *testing.T) {
	for _, raw := range []string{"http://example.net/list.csv", "https://user:pass@example.net/list.csv", "https://example.net/list.csv?token=secret", "https://example.net:444/list.csv"} {
		if validNetworkURL(raw) {
			t.Fatal(raw)
		}
	}
	if !validNetworkURL("https://example.net/list.csv") {
		t.Fatal("HTTPS rejected")
	}
	client := newNetworkClient()
	defer client.CloseIdleConnections()
	for _, target := range []string{"https://127.0.0.1/list.csv", "https://[::1]/list.csv", "https://10.0.0.1/list.csv"} {
		if _, e := fetchNetworkBody(context.Background(), client, target); e == nil {
			t.Fatal("private host reached", target)
		}
	}
}

// TestNetworkSpecialAddresses は共有・変換・試験用アドレスを公開接続と誤認しないことを検査する。
func TestNetworkSpecialAddresses(t *testing.T) {
	for _, raw := range []string{
		"0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.0.0.8", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:100.64.0.1", "64:ff9b::a00:1", "64:ff9b:1::1", "100::1",
		"2001::1", "2001:2::1", "2001:db8::1", "2002:a00:1::1", "3fff::1", "fc00::1", "fe80::1", "fe80::1%eth0", "ff02::1",
	} {
		if publicNetworkAddress(netip.MustParseAddr(raw)) {
			t.Errorf("special address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "100.63.255.255", "100.128.0.1", "198.17.255.255", "198.20.0.1", "::ffff:8.8.8.8", "2001:4860:4860::8888", "2606:4700:4700::1111"} {
		if !publicNetworkAddress(netip.MustParseAddr(raw)) {
			t.Errorf("public address rejected: %s", raw)
		}
	}
}

// TestNetworkFetchRejectsURLBeforeTransport は呼出元によらず取得入口でURLを拒否する。
func TestNetworkFetchRejectsURLBeforeTransport(t *testing.T) {
	client := &http.Client{Transport: networkTestTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid URL reached transport")
		return nil, errNetworkFetch
	})}
	for _, target := range []string{"http://example.net/list.csv", "https://user:pass@example.net/list.csv", "https://example.net:444/list.csv", "https://example.net/list.csv?secret=x", "https://example.net/list.csv?", "https://example.net/list.csv#", "https://example.net:/list.csv"} {
		if _, err := fetchNetworkBody(t.Context(), client, target); err == nil {
			t.Errorf("invalid URL accepted: %s", target)
		}
	}
}

// TestNetworkDNSDialBoundary はDNS回答の混在拒否と検査済みIPへの固定接続を検査する。
func TestNetworkDNSDialBoundary(t *testing.T) {
	public := netip.MustParseAddr("8.8.8.8")
	for _, addresses := range [][]netip.Addr{nil, {public, netip.MustParseAddr("10.0.0.1")}, {public, netip.MustParseAddr("100.64.0.1")}, {public, netip.MustParseAddr("64:ff9b::a00:1")}, {{}}, {public}} {
		lookups, dials := 0, 0
		lookup := func(ctx context.Context, family, host string) ([]netip.Addr, error) {
			lookups++
			if ctx != t.Context() || family != "ip" || host != "feed.example" {
				t.Fatal("lookup input changed")
			}
			return addresses, nil
		}
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			dials++
			if ctx != t.Context() || network != "tcp" || address != "8.8.8.8:443" {
				t.Fatal("DNS result not pinned", address)
			}
			return nil, errors.New("test dial stopped")
		}
		_, err := dialNetworkAddress(t.Context(), "tcp", "feed.example:443", lookup, dial)
		wantDials := 0
		if len(addresses) == 1 && addresses[0] == public {
			wantDials = 1
		}
		if err == nil || lookups != 1 || dials != wantDials {
			t.Fatalf("unexpected DNS/dial boundary: lookups=%d dials=%d err=%v", lookups, dials, err)
		}
	}
}
