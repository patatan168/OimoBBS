// 更新設定の保存でDNS確認を失い、保存済みなのに応答だけ403になる回帰を検証する。
package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"oimobbs/internal/identity"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type settingsAccessResolver struct {
	ip    netip.Addr
	calls atomic.Int32
}

// LookupAddr は外部照会せず架空名を返し、キャッシュの再取得回数を数える。
func (r *settingsAccessResolver) LookupAddr(context.Context, string) ([]string, error) {
	r.calls.Add(1)
	return []string{"client.example.invalid."}, nil
}

// LookupNetIP は試験内で指定したIPだけを返して正引き確認を再現する。
func (r *settingsAccessResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}

// networkSettingsBrowserTLS は標準試験証明書を使い、ブラウザーの対応するTLSと設定ファイルを揃える。
func networkSettingsBrowserTLS(t *testing.T, cfg *Config) *tls.Config {
	t.Helper()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	pair := fixture.TLS.Certificates[0]
	encoded, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	cfg.Public.TLSCert, cfg.Public.TLSKey = filepath.Join(directory, "server.pem"), filepath.Join(directory, "server.key")
	mustWrite(t, cfg.Public.TLSCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}))
	mustWrite(t, cfg.Public.TLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	return fixture.TLS.Clone()
}

// TestNetworkSettingsPreserveDNSAccess は空のOS標準設定を明示値で保存しても同じ接続を許可する。
func TestNetworkSettingsPreserveDNSAccess(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := client.request("GET", "/networks", "", nil)
	hidden := pageFields(page)
	// 公開DNSサーバーのIPを照会せず、架空の名前を返す固定resolverだけで確認する。
	ip := netip.MustParseAddr("8.8.8.8")
	resolver := &settingsAccessResolver{ip: ip}
	repo.networkHosts.Close()
	repo.networkHosts = identity.NewHostCache(resolver)
	repo.networkHosts.Resolve(t.Context(), ip)
	classifier := *repo.liveNetworks.Load()
	classifier.Services = repo.networkHosts
	repo.liveNetworks.Store(&classifier)
	policy := defaultReadingPolicy()
	policy.Enabled = true
	policy.Network.DenyUnresolvedHost = reverseFlag(true)
	compiled, err := compileReadingPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	repo.liveReading.Store(&readingSnapshot{Policies: map[string]*compiledReadingPolicy{"admin": compiled}})
	repo.cfg.Admin.Transport = "direct_https"
	handler := &adminHandler{repo: repo, auth: repo.adminAuth, origin: "https://localhost"}
	fields := url.Values{"action": {"settings"}, "enabled": {"false"}, "interval_hours": {"24"}, "dns_mode": {"system"}, "schedule_mode": {"daily"}, "schedule_time": {"04:00"}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {"schedule-dns-access-0001"}}
	request := httptest.NewRequest("POST", "https://localhost/networks", strings.NewReader(fields.Encode()))
	request.RemoteAddr = netip.AddrPortFrom(ip, 12345).String()
	request.Header.Set("Origin", "https://localhost")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(client.cookies["oimo_admin"])
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	view, err := repo.networkView()
	if response.Code != 200 || err != nil || view.Config.Schedule == nil || view.Config.Schedule.Time != "04:00" || view.Config.DNSMode != "system" {
		t.Fatal("settings response after save", response.Code, response.Body.String(), view.Config.Schedule, err)
	}
	if !repo.networkHosts.ReverseResolved(ip) || resolver.calls.Load() != 1 {
		t.Fatal("equivalent DNS settings discarded confirmation", resolver.calls.Load())
	}
	request = httptest.NewRequest("GET", "https://localhost/networks", nil)
	request.RemoteAddr = netip.AddrPortFrom(ip, 12345).String()
	request.Header.Set("Accept-Encoding", "gzip;q=0.1")
	request.AddCookie(client.cookies["oimo_admin"])
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal("saved page inaccessible", response.Code)
	}
	policy.DeniedCIDRs = []string{netip.PrefixFrom(ip, 32).String()}
	compiled, err = compileReadingPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	repo.liveReading.Store(&readingSnapshot{Policies: map[string]*compiledReadingPolicy{"admin": compiled}})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("explicit access restriction bypassed", response.Code)
	}
}
