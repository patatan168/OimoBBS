// 投稿時のDNS観測が署名原本・再起動・提出ZIPまで保存され、公開本文や未選択列へ漏れないことを確認する。
package bootstrap

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// reverseDNSConn は試験用socketの接続元だけを公開IPへ置き換える。転送ヘッダは採用しない。
type reverseDNSConn struct{ net.Conn }

func (c reverseDNSConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 54321}
}

func reverseDNSFormServer(t *testing.T, repo *Repository, owner domain.ID) *httptest.Server {
	t.Helper()
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "reverse-dns-test")
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := repo.SubmitLegacyRequest(r, owner, observer)
		if result.AnonymousCookie != nil {
			http.SetCookie(w, result.AnonymousCookie)
		}
		if result.Confirmation != nil {
			http.SetCookie(w, &http.Cookie{Name: "oimo_confirm", Value: result.Confirmation.Token, Path: "/"})
		}
		if result.Status != store.Durable && result.Confirmation == nil {
			w.WriteHeader(400)
		}
		_ = json.NewEncoder(w).Encode(formResult{result.ThreadKey, result.PostNumber, result.Duplicate, result.Status == store.Durable, result.Confirmation})
	}))
	s.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		return observer.ConnContext(ctx, reverseDNSConn{conn})
	}
	s.Start()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Client().Jar = anonymousOnlyJar{jar}
	return s
}

func reverseDNSRecords(t *testing.T, r *Repository, board domain.ID) []app.AcceptedEvidence {
	t.Helper()
	b := r.posting[board]
	v, err := b.worker.Submit(t.Context(), func() (any, error) { return app.AcceptedRecords(slices.Collect(maps.Values(b.journals))) })
	if err != nil {
		t.Fatal(err)
	}
	return v.([]app.AcceptedEvidence)
}

func TestPostingReverseDNSPersistsAndExports(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "逆引き原本"); err != nil {
		t.Fatal(err)
	}
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { r.Close() }()
	useHealthyPostingCapacity(t, r)
	board, err := r.CreateBoard(t.Context(), "reverse", "逆引き")
	if err != nil {
		t.Fatal(err)
	}
	r.networkHosts.Close()
	r.networkHosts = identity.NewHostCache(probeDNSResolver{names: []string{"POSTER.EXAMPLE."}, ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}})
	s := reverseDNSFormServer(t, r, board.ID)
	posted, err := sendForm(s, url.Values{"bbs": {"reverse"}, "subject": {"題"}, "MESSAGE": {"本文"}, "oimo_request_id": {"reverse-dns-post-001"}})
	s.Close()
	if err != nil || !posted.Accepted {
		t.Fatal(posted, err)
	}
	rows := reverseDNSRecords(t, r, board.ID)
	if len(rows) != 1 {
		t.Fatal("accepted record missing")
	}
	selected, err := rows[0].Project([]string{"connection"})
	if err != nil {
		t.Fatal(err)
	}
	observation := selected["connection"].(*evidence.HTTPObservation)
	if observation.Resolved.IP != "8.8.8.8" || observation.ReverseDNS == nil || observation.ReverseDNS.ConfirmedName != "poster.example" || observation.ReverseDNS.Status != "confirmed" {
		t.Fatalf("DNS missing: %+v", observation)
	}
	dns := *observation.ReverseDNS
	snapshot, err := r.Thread(t.Context(), board.ID, posted.Key)
	if err != nil || bytes.Contains(snapshot.DAT, []byte("poster.example")) {
		t.Fatal("reverse hostname leaked to DAT", err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	rows = reverseDNSRecords(t, r, board.ID)
	selected, err = rows[0].Project([]string{"connection"})
	if err != nil {
		t.Fatal(err)
	}
	after := selected["client"].(map[string]any)["reverse_dns"].(*evidence.ReverseDNSObservation)
	want, _ := json.Marshal(dns)
	got, _ := json.Marshal(after)
	if !bytes.Equal(want, got) {
		t.Fatal("DNS observation changed on restart")
	}
	if _, ok := r.networkHosts.Observation(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("export resolved DNS again")
	}
	private, err := rows[0].Project([]string{"content"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(private)
	if bytes.Contains(raw, []byte("poster.example")) || bytes.Contains(raw, []byte("reverse_dns")) {
		t.Fatal("unselected connection leaked")
	}
	assertReverseDNSZIP(t, cfg, rows[0], dns)
}

// assertReverseDNSZIP は実投稿の署名原本を保全してZIPを生成し、CSVの日時・説明と署名を検証する。
func assertReverseDNSZIP(t *testing.T, cfg Config, record app.AcceptedEvidence, dns evidence.ReverseDNSObservation) {
	t.Helper()
	seed, err := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := disclosure.Open(root, key)
	if err != nil {
		t.Fatal("open export store", err)
	}
	defer s.Close()
	now := time.Now()
	actor := domain.NewID()
	c, err := s.Create(disclosure.Case{Number: "DNS-001", Reason: "DNS保存試験", Scope: disclosure.Scope{Board: record.Board, Thread: record.Thread, From: record.Committed - 1, To: record.Committed + 1}}, actor, `"evidence:new"`, "dns-create", now)
	if err != nil {
		t.Fatal("create export case", err)
	}
	c, err = s.Hold(c.ID, actor, c.ETag(), "dns-hold", "保全", []app.AcceptedEvidence{record}, now)
	if err != nil {
		t.Fatal("hold posting evidence", err)
	}
	c, export, err := s.Generate(c.ID, actor, c.ETag(), "dns-export", "提出", []string{"connection"}, now)
	if err != nil {
		t.Fatal("generate export", err)
	}
	_, file, _, err := s.Download(c.ID, export.ID, actor, c.ETag(), "dns-download", "確認", now)
	if err != nil {
		t.Fatal("download export", err)
	}
	zipBytes, err := io.ReadAll(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = disclosure.VerifyZIP(bytes.NewReader(zipBytes), int64(len(zipBytes)), key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		reader, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name], err = io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	rows := evidenceCSVRows(t, files["records.csv"])
	if len(rows) != 1 {
		t.Fatal("CSV count")
	}
	row := rows[0]
	if row["client.reverse_dns.names"] != `["poster.example"]` || row["client.reverse_dns.confirmed_name"] != "poster.example" || row["client.reverse_dns.status"] != "confirmed" {
		t.Fatal("DNS CSV values", row)
	}
	if row["client.reverse_dns.observed_at_jst"] != time.Unix(0, int64(dns.ObservedAt)).In(domain.JST).Format(time.RFC3339Nano) {
		t.Fatal("DNS observation time changed")
	}
	if row["board_key"] != "reverse" {
		t.Fatal("board alias missing", row)
	}
	if !strings.Contains(string(files["readme.txt"]), "逆引きで取得したPTR") {
		t.Fatal("DNS column meaning missing")
	}
}
