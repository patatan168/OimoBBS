// 実mTLS接続でedge認証・endpoint保存・偽装拒否を検査する。
package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func proxyCertificates(t *testing.T, cfg *Config) (*tls.Config, tls.Certificate) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	ca, e := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(ca)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	issue := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		t.Helper()
		leafPub, leafKey, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		raw, e := x509.CreateCertificate(rand.Reader, template, root, leafPub, key)
		if e != nil {
			t.Fatal(e)
		}
		encoded, e := x509.MarshalPKCS8PrivateKey(leafKey)
		if e != nil {
			t.Fatal(e)
		}
		certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil {
			t.Fatal(e)
		}
		return pair, certPEM, keyPEM
	}
	_, serverCert, serverKey := issue(2, x509.ExtKeyUsageServerAuth)
	client, _, _ := issue(3, x509.ExtKeyUsageClientAuth)
	other, _, _ := issue(4, x509.ExtKeyUsageClientAuth)
	directory := t.TempDir()
	cfg.Public.BaseURL = "https://localhost:9080"
	cfg.Public.TLSCert, cfg.Public.TLSKey = filepath.Join(directory, "server.pem"), filepath.Join(directory, "server.key")
	mustWrite(t, cfg.Public.TLSCert, serverCert)
	mustWrite(t, cfg.Public.TLSKey, serverKey)
	caFile := filepath.Join(directory, "client-ca.pem")
	mustWrite(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}))
	digest := sha256.Sum256(client.Certificate[0])
	cfg.Edge = &EdgeConfig{ID: "test-edge", Revision: 1, ClientCA: caFile, CertificateSHA256: hex.EncodeToString(digest[:])}
	cfg.TrustedProxies = []string{"127.0.0.1/32"}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{client}}, other
}

func edgeTestHeaders() http.Header {
	return http.Header{"X-Oimo-Client-Ip": {"192.0.2.19"}, "X-Oimo-Client-Port": {"45678"}, "X-Oimo-Dest-Ip": {"192.0.2.20"}, "X-Oimo-Dest-Port": {"443"}, "X-Oimo-Edge-Request": {"edge-request-1"}, "X-Oimo-Edge-Time": {"1790000000000000000"}, "X-Forwarded-For": {"192.0.2.19"}}
}

func TestAuthenticatedEdgeTLSAndPosting(t *testing.T) {
	cfg := testConfig(t)
	clientTLS, other := proxyCertificates(t, &cfg)
	initialized, e := Initialize(cfg, "認証edge")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	board, e := repo.CreateBoard(t.Context(), "edge", "edge板")
	if e != nil {
		t.Fatal(e)
	}
	serverConfig, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	observer, e := evidence.NewHTTPObserver(initialized.SiteID, domain.NewID(), "edge-test")
	if e != nil {
		t.Fatal(e)
	}
	observations := make(chan evidence.HTTPObservation, 1)
	serverConfig.ConnContext = observer.ConnContext
	serverConfig.Handler = cfg.edgeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/observe" {
			captured, e := observer.Begin(r, board.ID, "bbs_post", "localhost:9080")
			if e != nil {
				t.Error(e)
				http.Error(w, "capture", 400)
				return
			}
			io.Copy(io.Discard, r.Body)
			value, e := captured.Finish()
			if e != nil {
				t.Error(e)
				http.Error(w, "finish", 400)
				return
			}
			observations <- value
			w.WriteHeader(204)
			return
		}
		result := repo.SubmitLegacyRequest(r, board.ID, observer)
		if result.Confirmation != nil {
			http.SetCookie(w, &http.Cookie{Name: "oimo_confirm", Value: result.Confirmation.Token, Path: "/", Secure: true, HttpOnly: true})
		}
		if result.Status != store.Durable && result.Confirmation == nil {
			w.WriteHeader(400)
		}
		json.NewEncoder(w).Encode(formResult{result.ThreadKey, result.PostNumber, result.Duplicate, result.Status == store.Durable, result.Confirmation})
	}))
	server := httptest.NewUnstartedServer(serverConfig.Handler)
	server.Config = serverConfig
	server.TLS = serverConfig.TLSConfig.Clone()
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: clientTLS}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request := func(path, body string, headers http.Header, token string) (*http.Response, string, error) {
		t.Helper()
		req, _ := http.NewRequest("POST", server.URL+path, strings.NewReader(body))
		req.Host = "localhost:9080"
		req.Header = headers.Clone()
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		if token != "" {
			req.AddCookie(&http.Cookie{Name: "oimo_confirm", Value: token})
		}
		res, e := client.Do(req)
		if e != nil {
			return nil, "", e
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(res.Body)
		return res, string(raw), e
	}
	headers := edgeTestHeaders()
	res, body, e := request("/observe", "MESSAGE=hello", headers, "")
	if e != nil || res.StatusCode != 204 {
		t.Fatal(res, body, e)
	}
	observed := <-observations
	raw, _ := json.Marshal(observed)
	if e = evidence.ValidateHTTPObservation(raw); e != nil {
		t.Fatal(e)
	}
	if observed.Resolved.IP != "192.0.2.19" || observed.Resolved.Port != 45678 || observed.Peer.IP != "127.0.0.1" || observed.ClientSource != "edge_endpoint_v1" || observed.OriginEndpoint.Port != 443 || *observed.ProxyConfigRevision != 1 || !strings.Contains(*observed.ProxyProfileID, cfg.Edge.CertificateSHA256) {
		t.Fatal(observed)
	}
	fields := url.Values{"bbs": {"edge"}, "subject": {"認証済み投稿"}, "MESSAGE": {"edge経由本文"}, "oimo_request_id": {"edge-create-0001"}}
	res, body, e = request("/test/bbs.cgi", fields.Encode(), headers, "")
	var pending formResult
	if e != nil || json.Unmarshal([]byte(body), &pending) != nil || pending.Confirmation == nil {
		t.Fatal(res, body, e)
	}
	token := ""
	for _, cookie := range res.Cookies() {
		if cookie.Name == "oimo_confirm" {
			token = cookie.Value
		}
	}
	if token == "" {
		t.Fatal("confirmation cookie missing")
	}
	res, body, e = request("/test/bbs.cgi", fields.Encode(), headers, token)
	var accepted formResult
	if e != nil || json.Unmarshal([]byte(body), &accepted) != nil || !accepted.Accepted {
		t.Fatal(res, body, e)
	}
	for _, kind := range []string{"missing", "duplicate", "xff", "forwarded"} {
		invalid := headers.Clone()
		switch kind {
		case "missing":
			invalid.Del("X-Oimo-Client-Port")
		case "duplicate":
			invalid.Add("X-Oimo-Client-Port", "1234")
		case "xff":
			invalid.Set("X-Forwarded-For", "192.0.2.99")
		case "forwarded":
			invalid.Set("Forwarded", "for=192.0.2.19")
		}
		res, body, e = request("/test/bbs.cgi", fields.Encode(), invalid, "")
		if e != nil || res.StatusCode != 400 {
			t.Fatal(kind, res, body, e)
		}
	}
	transport.CloseIdleConnections()
	transport.TLSClientConfig = clientTLS.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{other}
	if _, _, e = request("/observe", "", headers, ""); e == nil {
		t.Fatal("another CA-signed edge certificate accepted")
	}
	transport.CloseIdleConnections()
	transport.TLSClientConfig = clientTLS.Clone()
	transport.TLSClientConfig.Certificates = nil
	if _, _, e = request("/observe", "", headers, ""); e == nil {
		t.Fatal("unauthenticated TLS client accepted")
	}
	server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	records, e := reopened.collectEvidence(t.Context(), disclosure.Scope{Board: board.ID, Thread: domain.U64(accepted.Key), From: 1, To: domain.Time(time.Now().Add(time.Second).UnixNano()), Records: []domain.ID{}})
	if e != nil || len(records) != 1 {
		t.Fatal(records, e)
	}
	connection, projectionErr := records[0].Project([]string{"connection"})
	if projectionErr != nil {
		t.Fatal(projectionErr)
	}
	original := connection["connection"]
	encoded, _ := json.Marshal(original)
	if !strings.Contains(string(encoded), "192.0.2.19") || !strings.Contains(string(encoded), "45678") {
		t.Fatal(string(encoded))
	}
	snapshot, e := reopened.Thread(t.Context(), board.ID, accepted.Key)
	if e != nil || snapshot == nil || snapshot.Title != "認証済み投稿" {
		t.Fatal(snapshot, e)
	}
}

func TestEdgeConfigurationRejectsWeakTrust(t *testing.T) {
	cfg := testConfig(t)
	proxyCertificates(t, &cfg)
	for _, raw := range []string{"0.0.0.0/0", "127.0.0.1", "127.0.0.1/24"} {
		changed := cfg
		changed.TrustedProxies = []string{raw}
		if e := changed.validate(); e == nil {
			t.Fatal(raw)
		}
	}
	cfg.Public.BaseURL = "http://127.0.0.1:9080"
	if e := cfg.validate(); e == nil {
		t.Fatal("plaintext authenticated edge accepted")
	}
	// 通常直結では任意の転送値から利用者endpointを合成しない。
	req := httptest.NewRequest("GET", "http://example.org/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header = edgeTestHeaders()
	if evidence.ClientRemoteAddr(req) != req.RemoteAddr {
		t.Fatal("direct forwarded headers trusted")
	}
}

func TestInvalidEdgeCADoesNotPromoteReader(t *testing.T) {
	cfg := testConfig(t)
	proxyCertificates(t, &cfg)
	if _, e := Initialize(cfg, "edge起動拒否"); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	before := repo.site.State().Seq
	if e = os.WriteFile(cfg.Edge.ClientCA, []byte("invalid CA"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ValidationHTTPServer(); e == nil {
		t.Fatal("invalid CA accepted")
	}
	if after := repo.site.State().Seq; after != before {
		t.Fatal("failed edge startup changed site control", before, after)
	}
}
