// 製品と共有するHTTPサーバーから署名file、管理集計、終了・再起動までを検証する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func optionalProductServer(t *testing.T, repo *Repository) *httptest.Server {
	t.Helper()
	public, e := repo.ValidationHTTPServer()
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(public.Handler)
	s.Config.ConnContext = public.ConnContext
	s.Start()
	return s
}

func optionalProductRecords(t *testing.T, cfg Config, site domain.ID) []evidence.OptionalRecord {
	t.Helper()
	seed, e := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	root := filepath.Join(cfg.DataDir, "reports", "http")
	if e = evidence.InspectOptionalStore(root, site, key); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	var records []evidence.OptionalRecord
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == evidence.OptionalHoldsDirectory {
			continue
		}
		day, _ := strconv.ParseUint(entry.Name(), 10, 64)
		state, e := store.InspectControl(filepath.Join(root, entry.Name()), 8, evidence.OptionalOwner(site), day, func(string, string, json.RawMessage, json.RawMessage) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		for _, row := range state.Rows {
			var event evidence.Event
			if e = json.Unmarshal(row.Value, &event); e != nil {
				t.Fatal(e)
			}
			raw, e := base64.StdEncoding.Strict().DecodeString(event.Payload)
			if e != nil {
				t.Fatal(e)
			}
			var p evidence.OptionalPayload
			if e = json.Unmarshal(raw, &p); e != nil {
				t.Fatal(e)
			}
			records = append(records, p.Record)
			for _, secret := range []string{"PRIVATE_POST_BODY", "UNKNOWN_FORM_SECRET", "QUERY_SECRET", "COOKIE_SECRET", "AUTH_SECRET", "trip-private-secret"} {
				if strings.Contains(string(raw), secret) {
					t.Fatal("optional log contains private input", secret)
				}
			}
		}
	}
	return records
}

func TestOptionalLogsProductLifecycle(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	board, e := repo.CreateBoard(context.Background(), "logs", "ログ")
	if e != nil {
		t.Fatal(e)
	}
	site := siteID(repo.site.State())
	server := optionalProductServer(t, repo)
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cookies := map[string]*http.Cookie{}
	request := func(method, path string, fields url.Values) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(fields.Encode()))
		req.Host = "127.0.0.1:9080"
		req.Header.Set("User-Agent", "product-log-test")
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			req.Header.Set("Origin", cfg.Public.BaseURL)
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		response, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		raw, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		for _, cookie := range response.Cookies() {
			cookies[cookie.Name] = cookie
		}
		return response, string(raw)
	}
	cookies["unrelated"] = &http.Cookie{Name: "unrelated", Value: "COOKIE_SECRET"}
	response, _ := request("GET", "/?QUERY_SECRET=x", nil)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	response, _ = request("GET", "/logs/", nil)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	fields := url.Values{"bbs": {"logs"}, "subject": {"確認"}, "FROM": {"投稿者#trip-private-secret"}, "MESSAGE": {"PRIVATE_POST_BODY"}, "unknown": {"UNKNOWN_FORM_SECRET"}, "oimo_request_id": {"optional-product-01"}}
	response, body := request("POST", "/test/bbs.cgi", fields)
	if response.StatusCode != 200 || !strings.Contains(body, "2ch_X:cookie") {
		t.Fatal("confirmation", response.StatusCode, body)
	}
	response, body = request("POST", "/test/bbs.cgi", fields)
	if response.StatusCode != 200 || !strings.Contains(body, "/test/read.cgi/logs/") {
		t.Fatal("accepted", response.StatusCode, body)
	}
	response, body = request("POST", "/test/bbs.cgi", fields)
	if response.StatusCode != 200 || !strings.Contains(body, "/test/read.cgi/logs/") {
		t.Fatal("duplicate", response.StatusCode, body)
	}
	fields.Set("bbs", "missing")
	response, _ = request("POST", "/test/bbs.cgi", fields)
	if response.StatusCode != 200 {
		t.Fatal("legacy rejected status", response.StatusCode)
	}
	rows, e := repo.collectEvidence(context.Background(), disclosure.Scope{Board: board.ID, From: domain.Time(time.Now().Add(-time.Hour).UnixNano()), To: domain.Time(time.Now().Add(time.Minute).UnixNano()), Records: []domain.ID{}})
	if e != nil || len(rows) != 1 {
		t.Fatal("mandatory evidence", len(rows), e)
	}
	var proposal struct {
		Capture postcapture.Capture `json:"capture"`
	}
	if e = json.Unmarshal(rows[0].Proposal.Payload, &proposal); e != nil {
		t.Fatal(e)
	}
	server.Close()
	if e = repo.optionalQueue.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	status := repo.OptionalHTTPLogs()
	if !status.Active || status.CleanupFailed || status.Queue.Saved != 10 || status.Queue.Failed != 0 {
		t.Fatal(status)
	}
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("admin login")
	}
	response, body = admin.request("GET", "/api/v1/maintenance", "", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "optional_http_logs") || !strings.Contains(body, `"saved":10`) {
		t.Fatal("metrics", response.StatusCode, body)
	}
	response, body = admin.request("GET", "/maintenance", "", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "HTTPログの保存") {
		t.Fatal("metrics HTML", response.StatusCode, body)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo = nil
	records := optionalProductRecords(t, cfg, site)
	outcomes := map[string]int{}
	for _, r := range records {
		outcomes[r.Outcome]++
		if r.Outcome == "accepted" || r.Outcome == "duplicate" {
			if r.Operation == nil || *r.Operation != rows[0].Operation || r.Board == nil || *r.Board != board.ID {
				t.Fatal("posting link", r)
			}
			if r.Outcome == "accepted" && (r.Request != proposal.Capture.Observation.RequestID || r.Connection != proposal.Capture.Observation.ConnectionID || r.Received != proposal.Capture.Observation.Received) {
				t.Fatal("mandatory request link", r, proposal.Capture)
			}
		}
		if r.Route == "board" && (r.Board == nil || *r.Board != board.ID) {
			t.Fatal("read board missing")
		}
	}
	if outcomes["accepted"] != 2 || outcomes["duplicate"] != 2 || outcomes["confirmation"] != 2 || outcomes["rejected"] != 2 || outcomes["served"] != 2 {
		t.Fatal(outcomes)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if !repo.OptionalHTTPLogs().Active || repo.OptionalHTTPLogs().Queue.Saved != 0 {
		t.Fatal("restart lifecycle")
	}
}

func TestOptionalLogActivationResumeAndMissingActiveRoot(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "途中起動"); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	var site siteState
	if e = json.Unmarshal(repo.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	site.MinimumReader = 39
	activation := optionalLogActivation{Schema: "optional-http-activation-v1", Site: site.ID, Phase: "preparing"}
	if e = appendControl(repo.site, "optional_http_prepare", []store.Mutation{mutation("site", "state", site, nil), mutation("optional_http", "http", activation, nil)}, []string{}); e != nil {
		t.Fatal(e)
	}
	repo.Close()
	if _, e = Check(cfg); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("check completed activation", e)
	}
	if _, e = os.Stat(filepath.Join(cfg.DataDir, "reports", "http")); !os.IsNotExist(e) {
		t.Fatal("check created root", e)
	}
	repo, e = OpenRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if !repo.OptionalHTTPLogs().Active {
		t.Fatal("preparing not resumed")
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = Check(cfg); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(cfg.DataDir, "reports", "http")); e != nil {
		t.Fatal(e)
	}
	if repo, e = OpenRepository(cfg); e == nil {
		repo.Close()
		t.Fatal("active missing root recreated")
	}
}

func TestOptionalLogFailureDoesNotRejectMandatoryPosting(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	board, e := repo.CreateBoard(context.Background(), "safe", "必須保存")
	if e != nil {
		t.Fatal(e)
	}
	server := optionalProductServer(t, repo)
	defer server.Close()
	candidate := filepath.Join(cfg.DataDir, "reports", optionalLossDir, "loss.pending")
	if e = os.Mkdir(candidate, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(candidate)
	repo.snapshotOptionalLoss()
	if !repo.OptionalHTTPLogs().Loss.PersistFailed {
		t.Fatal("loss persistence fault not reported")
	}
	root := filepath.Join(cfg.DataDir, "reports", "http")
	if e = os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(root, 0700)
	var confirmation []*http.Cookie
	send := func() string {
		t.Helper()
		fields := url.Values{"bbs": {"safe"}, "subject": {"失敗分離"}, "MESSAGE": {"PRIVATE_POST_BODY"}, "oimo_request_id": {"optional-failure-01"}}
		req, _ := http.NewRequest("POST", server.URL+"/test/bbs.cgi", strings.NewReader(fields.Encode()))
		req.Host = "127.0.0.1:9080"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		for _, c := range confirmation {
			req.AddCookie(c)
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(res.Body)
		if e != nil {
			t.Fatal(e)
		}
		confirmation = res.Cookies()
		return string(raw)
	}
	if body := send(); !strings.Contains(body, "2ch_X:cookie") {
		t.Fatal(body)
	}
	if body := send(); !strings.Contains(body, "/test/read.cgi/safe/") {
		t.Fatal("optional failure affected accepted post", body)
	}
	server.Close()
	if e = repo.optionalQueue.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	status := repo.OptionalHTTPLogs()
	if status.Queue.Failed != 4 || status.Queue.Saved != 0 || status.Queue.Pending != 0 || status.Queue.LossStarted == 0 {
		t.Fatal(status)
	}
	rows, e := repo.collectEvidence(context.Background(), disclosure.Scope{Board: board.ID, From: domain.Time(time.Now().Add(-time.Hour).UnixNano()), To: domain.Time(time.Now().Add(time.Minute).UnixNano()), Records: []domain.ID{}})
	if e != nil || len(rows) != 1 {
		t.Fatal("mandatory signature evidence missing", len(rows), e)
	}
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
}

func TestOptionalActivationSnapshotAndTransitions(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "snapshot"); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ValidationHTTPServer(); e != nil {
		t.Fatal(e)
	}
	state := repo.site.State()
	row := state.Rows["optional_http:http"]
	if e = snapshotSiteValue("optional_http", "http", nil, row.Value); e != nil {
		t.Fatal("active snapshot rejected", e)
	}
	if e = validateSiteValue("optional_http", "http", nil, row.Value); e == nil {
		t.Fatal("active without prepare accepted")
	}
	if e = validateSiteValue("optional_http", "http", row.Value, row.Value); e == nil {
		t.Fatal("active changed again")
	}
	if e = snapshotSiteValue("optional_http", "http", row.Value, row.Value); e == nil {
		t.Fatal("snapshot duplicate accepted")
	}
	raw, e := store.EncodeControlSnapshot(store.Header{Kind: 1, Owner: siteID(state), Generation: 2, BaseSeq: uint64(state.Seq)}, state, 6, snapshotSiteValue)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := store.DecodeControlSnapshot(raw, store.Header{Kind: 1, Owner: siteID(state), Generation: 2, BaseSeq: uint64(state.Seq)}, snapshotSiteValue)
	if e != nil || string(decoded.Rows["optional_http:http"].Value) != string(row.Value) {
		t.Fatal("snapshot state", e)
	}
	repo.Close()
	repo, e = OpenRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	if !repo.OptionalHTTPLogs().Active {
		t.Fatal("snapshot lost log activation")
	}
}

func TestOptionalLogsStartupCollectsExpiredDayAfterReadOnlyCheck(t *testing.T) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "期限回収")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ValidationHTTPServer(); e != nil {
		t.Fatal(e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	seed, e := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	received := time.Now().Add(-8 * 24 * time.Hour)
	dayText := received.UTC().Format("20060102")
	day, _ := strconv.ParseUint(dayText, 10, 64)
	root := filepath.Join(cfg.DataDir, "reports", "http")
	path := filepath.Join(root, dayText)
	j, e := evidence.OpenJournal(path, evidence.OptionalOwner(report.SiteID), day, 10, key, evidence.ValidateOptionalPayload)
	if e != nil {
		t.Fatal(e)
	}
	record := evidence.OptionalRecord{Schema: "optional-http-v1", ID: domain.NewID(), Site: report.SiteID, Boot: domain.NewID(), Connection: domain.NewID(), Request: domain.NewID(), Received: domain.Time(received.UnixNano()), Finished: domain.Time(received.UnixNano() + 100), Until: domain.Time(received.Add(evidence.OptionalRetention).UnixNano()), Peer: evidence.Endpoint{IP: "192.0.2.1", Port: 12345}, Local: evidence.Endpoint{IP: "192.0.2.2", Port: 443}, Method: "GET", Route: "home", Kind: "access", Outcome: "served", Status: 200, UAStatus: "captured", HTTPVersion: "HTTP/1.1", FinishStage: "handler_return"}
	_, result := j.Append(record.ID, "receipt", record.Received, func(src evidence.Source) ([]byte, error) {
		return json.Marshal(evidence.OptionalPayload{Owner: src.Owner, Day: domain.U64(src.Subkey), Seq: domain.U64(src.Seq), Record: record})
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	j.Close()
	wal := filepath.Join(path, "control-000001.wal")
	before, e := os.ReadFile(wal)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Check(cfg); e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadFile(wal)
	if e != nil || string(before) != string(after) {
		t.Fatal("check removed expired original", e)
	}
	repo, e = OpenRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("startup did not collect expired day", e)
	}
	if _, e = os.Stat(filepath.Join(root, dayText+".checkpoint.json")); e != nil {
		t.Fatal("checkpoint missing", e)
	}
	if repo.OptionalHTTPLogs().CleanupFailed {
		t.Fatal("cleanup failed")
	}
}

// TestOptionalLogReservationPreservesPostingHeadroom は非必須作業が最後の必須投稿枠を使わないことを検査する。
func TestOptionalLogReservationPreservesPostingHeadroom(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	floor := uint64(1 << 30)
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: floor + postingReservationBytes}, nil
	}
	if _, e := r.reservePrivateLogBytes(256 << 10); !errors.Is(e, ErrPostingCapacity) {
		t.Fatal("optional consumed essential headroom", e)
	}
	if !r.PostingCapacity().WriteReady {
		t.Fatal("optional rejection blocked posting")
	}
	release, e := r.reservePosting()
	if e != nil {
		t.Fatal(e)
	}
	release()
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: floor + postingReservationBytes + (256 << 10)}, nil
	}
	release, e = r.reservePrivateLogBytes(256 << 10)
	if e != nil {
		t.Fatal(e)
	}
	posting, e := r.reservePosting()
	if e != nil {
		release()
		t.Fatal("optional reservation blocked mandatory posting", e)
	}
	posting()
	release()
	if r.postReserved != 0 {
		t.Fatal("reservation leaked", r.postReserved)
	}
}

// 満了回収は投稿停止の閾値内でも進め、他の保存予約を奪わない。
func TestOptionalReclaimReservationBelowPostingFloor(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 1 << 20}, nil
	}
	if r.PostingCapacity().WriteReady {
		t.Fatal("posting admitted below floor")
	}
	release, e := r.reservePrivateReclaimBytes(128 << 10)
	if e != nil {
		t.Fatal("small terminal reclaim stopped with posting", e)
	}
	if r.postReserved != 128<<10 {
		t.Fatal("missing reclaim reservation")
	}
	if _, e = r.reservePrivateReclaimBytes(1 << 20); !errors.Is(e, ErrPostingCapacity) {
		release()
		t.Fatal("existing reservation consumed", e)
	}
	release()
	release()
	if r.postReserved != 0 {
		t.Fatal("reclaim reservation leaked")
	}
	if r.PostingCapacity().WriteReady {
		t.Fatal("GC enabled posting without recovery")
	}
}

// 新しい元保全領域を旧readerのHTTP履歴として黙って受け入れない。
func TestOptionalSourceHoldReaderGate(t *testing.T) {
	cfg, repo := adminFixture(t)
	public := optionalProductServer(t, repo)
	public.Close()
	state := repo.site.State()
	var site siteState
	if e := json.Unmarshal(state.Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory)
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	// 公開受付が有効化した新しい形式は保持し、対象領域のreader境界だけを検査する。
	site.MinimumReader = 41
	if e := inspectOptionalLogs(cfg, site, state, false); e == nil || !strings.Contains(e.Error(), "reader42") {
		t.Fatal("old reader accepted source holds", e)
	}
	site.MinimumReader = 42
	if e := inspectOptionalLogs(cfg, site, state, false); e != nil {
		t.Fatal("reader42 rejected known reservation root", e)
	}
	if _, e := Check(cfg); e != nil {
		t.Fatal("current product rejected reservation root", e)
	}
}
