// Package bootstrap は永続サイトの初期化と、公開開始前の読取り検査を行う。
package bootstrap

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/delivery"
	"oimobbs/internal/strictjson"
)

// Config は起動専用の設定。板・管理者などの可変状態は含めない。
type Config struct {
	AutoReports    *AutoReportConfig      `json:"auto_reports"`
	Edge           *EdgeConfig            `json:"edge"`
	Maintenance    *PackMaintenanceConfig `json:"maintenance"`
	Schema         uint32                 `json:"schema_version"`
	DataDir        string                 `json:"data_dir"`
	Public         PublicConfig           `json:"public"`
	Admin          AdminConfig            `json:"admin"`
	TrustedProxies []string               `json:"trusted_proxies"`
	CacheBytes     uint64                 `json:"cache_bytes"`
	EgressBits     uint64                 `json:"egress_budget_bits_per_second"`
}

// PublicConfig は公開originとTLS終端を指定する。
type PublicConfig struct {
	Listen  string `json:"listen"`
	BaseURL string `json:"base_url"`
	TLSCert string `json:"tls_cert_file"`
	TLSKey  string `json:"tls_key_file"`
}

// AdminConfig はローカル待受・公開管理パス・別HTTPS待受の管理接続を指定する。HTTPSは公開用TLSを使う。
type AdminConfig struct {
	Listen    string `json:"listen"`
	Transport string `json:"transport"`
	Origin    string `json:"origin"`
}

// LoadConfig は64KiB以内の厳格JSONを読み、相対pathを設定ファイルの場所から解決する。
// 全項目を必須とし、未使用の設定は明示nullで指定する。旧項目の欠落を補完しない。
func LoadConfig(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil {
		return cfg, err
	}
	if len(b) > 64<<10 {
		return cfg, errors.New("config exceeds 64 KiB")
	}
	if err = strictjson.Decode(b, &cfg); err != nil {
		return cfg, err
	}
	if cfg.DataDir == "" {
		return cfg, errors.New("data_dir required")
	}
	root, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return cfg, err
	}
	for _, p := range []*string{&cfg.DataDir, &cfg.Public.TLSCert, &cfg.Public.TLSKey} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(root, *p)
		}
	}
	if cfg.Edge != nil && cfg.Edge.ClientCA != "" && !filepath.IsAbs(cfg.Edge.ClientCA) {
		cfg.Edge.ClientCA = filepath.Join(root, cfg.Edge.ClientCA)
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	if c.AutoReports != nil {
		if !validBoardKey(c.AutoReports.BoardKey) {
			return errors.New("invalid automatic report board")
		}
		if at, err := time.Parse(time.RFC3339, c.AutoReports.Since); err != nil || at.UnixNano() <= 0 || at.After(time.Now()) {
			return errors.New("automatic reports require a past RFC3339 activation time")
		}
	}
	if m := c.Maintenance; m != nil && (m.MaxSeconds < 0 || m.MaxSeconds > 300 || m.IntervalSeconds < 60 || m.IntervalSeconds > 86400 || m.MaxThreads < 1 || m.MaxThreads > 1000) {
		return errors.New("invalid maintenance interval or batch limit")
	}
	if c.Schema != 1 || !filepath.IsAbs(c.DataDir) || filepath.Clean(c.DataDir) != c.DataDir || c.DataDir == "/" || c.CacheBytes == 0 || c.CacheBytes > 1<<40 || c.EgressBits == 0 || c.EgressBits > delivery.MaxBudgetBits {
		return errors.New("invalid schema, data directory, or resource budget")
	}
	if e := c.validateEdge(); e != nil {
		return e
	}
	pub, err := parseOrigin(c.Public.BaseURL)
	if err != nil {
		return fmt.Errorf("public origin: %w", err)
	}
	adm, adminPath, err := c.adminEndpoint()
	if err != nil {
		return fmt.Errorf("admin origin: %w", err)
	}
	pHost, pPort, err := listenParts(c.Public.Listen)
	if err != nil {
		return err
	}
	var aHost string
	var aPort uint16
	if c.Admin.Transport != "public_path" {
		aHost, aPort, err = listenParts(c.Admin.Listen)
		if err != nil {
			return err
		}
	}
	switch c.Admin.Transport {
	case "loopback_tunnel":
		if !loopback(aHost) || adm.Scheme != "http" || !loopback(adm.Hostname()) {
			return errors.New("admin requires a loopback HTTP origin and loopback_tunnel listener")
		}
	case "public_path":
		if normalizedOrigin(pub) != normalizedOrigin(adm) || adminPath == "" {
			return errors.New("shared admin requires the public origin and a private path")
		}
	case "direct_https":
		if adm.Scheme != "https" || pub.Scheme != "https" || c.Public.TLSCert == "" || c.Public.TLSKey == "" {
			return errors.New("public admin requires HTTPS and a certificate valid for both origins")
		}
	default:
		return errors.New("unsupported admin transport")
	}
	if c.Admin.Transport != "public_path" && (normalizedOrigin(pub) == normalizedOrigin(adm) || pPort == aPort && (pHost == aHost || pHost == "" || pHost == "0.0.0.0" || pHost == "::")) {
		return errors.New("public and admin endpoints must be separate")
	}
	if c.Edge != nil && pub.Scheme != "https" {
		return errors.New("authenticated edge requires HTTPS on both hops")
	}
	if pub.Scheme == "http" {
		if !loopback(pHost) || !loopback(pub.Hostname()) || c.Public.TLSCert != "" || c.Public.TLSKey != "" {
			return errors.New("HTTP is restricted to explicit loopback testing without TLS files")
		}
		return nil
	}
	if c.Public.TLSCert == "" || c.Public.TLSKey == "" {
		return errors.New("HTTPS requires certificate and private key files")
	}
	return nil
}
func parseOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("HTTP(S) origin without path, query, or userinfo required")
	}
	host := u.Hostname()
	if strings.Contains(host, "%") || host == "" {
		return nil, errors.New("invalid origin host")
	}
	for _, c := range host {
		if c > 127 || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".:-", c)) {
			return nil, errors.New("ASCII origin host required")
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("empty origin port")
	}
	if u.Port() != "" {
		if _, err = validPort(u.Port()); err != nil {
			return nil, err
		}
	}
	return u, nil
}
func normalizedOrigin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}
func validPort(raw string) (uint16, error) {
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != raw {
		return 0, errors.New("canonical port 1..65535 required")
	}
	return uint16(n), nil
}
func listenParts(addr string) (string, uint16, error) {
	host, raw, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	if host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return "", 0, errors.New("listen host must be an IP literal")
		}
	}
	port, err := validPort(raw)
	return host, port, err
}
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == "" && ip.IsLoopback()
}

// checkTLS は公開HTTPSの鍵・証明書・名前・有効期間を検査し、ネットワークへ接続しない。
func (c Config) checkTLS(now time.Time) error {
	if c.Public.TLSKey == "" {
		return nil
	}
	if _, err := c.loadTLSCertificate(now); err != nil {
		return err
	}
	if c.Admin.Transport == "direct_https" {
		_, err := c.loadAdminTLSCertificate(now)
		return err
	}
	return nil
}

// loadTLSCertificate は返す同じpairの名前・期限・秘密鍵配置を検査し、再読込による差替えを挟まない。
func (c Config) loadTLSCertificate(now time.Time) (*tls.Certificate, error) {
	if err := privatePath(c.Public.TLSKey, false); err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(c.Public.TLSCert, c.Public.TLSKey)
	if err != nil {
		return nil, errors.New("cannot load public TLS certificate/key pair")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	u, err := parseOrigin(c.Public.BaseURL)
	if err != nil {
		return nil, err
	}
	if err = cert.VerifyHostname(u.Hostname()); err != nil {
		return nil, errors.New("TLS certificate does not match public origin")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("TLS certificate is outside its validity period")
	}
	pair.Leaf = cert
	return &pair, nil
}

// noNull はnullを通常のobjectとして受理しないために使う。
func noNull(b []byte) bool { return len(b) > 0 && !bytes.Equal(bytes.TrimSpace(b), []byte("null")) }

// loadAdminTLSCertificate は共有証明書を管理Originの名前と期限でも照合する。
// 更新後の証明書が管理名を失った場合も、新しいTLS接続を拒否する。
func (c Config) loadAdminTLSCertificate(now time.Time) (*tls.Certificate, error) {
	c.Public.BaseURL = c.Admin.Origin
	return c.loadTLSCertificate(now)
}

// adminEndpoint は公開パス方式だけURLの末尾を管理専用のマウント先として分離する。
// 通常のorigin検証を維持し、符号化・曖昧なパスや公開ルートとの衝突を拒否する。
func (c Config) adminEndpoint() (*url.URL, string, error) {
	if c.Admin.Transport != "public_path" {
		u, err := parseOrigin(c.Admin.Origin)
		return u, "", err
	}
	u, err := url.Parse(c.Admin.Origin)
	if err != nil {
		return nil, "", err
	}
	base := strings.TrimSuffix(u.Path, "/")
	if (base != "/admin" && (len(base) < 17 || boardKeyPattern.MatchString(strings.TrimPrefix(base, "/")))) || len(base) > 129 || strings.Contains(c.Admin.Origin, "#") || u.RawPath != "" || !strings.HasPrefix(base, "/") || strings.Contains(base[1:], "/") {
		return nil, "", errors.New("admin path must be /admin or one 16-128 character ASCII segment distinct from board keys")
	}
	for _, ch := range base[1:] {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return nil, "", errors.New("invalid admin path")
		}
	}
	u.Path = ""
	origin, err := parseOrigin(u.String())
	return origin, base, err
}
