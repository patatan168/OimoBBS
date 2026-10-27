// 運用設定の実HTTP保存、再送、競合、再起動と共有処理への反映を検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/delivery"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOperationsHTTPPersistenceAndLiveLimits(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	if _, e := repo.CreateBoard(t.Context(), "report", "通報"); e != nil {
		t.Fatal(e)
	}
	repo.Close()
	cfg.AutoReports = &AutoReportConfig{"report", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	res, _ := client.request("GET", "/operations", "", nil)
	if res.StatusCode != 401 {
		t.Fatal("anonymous operations")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := client.request("GET", "/api/v1/operations", "", nil)
	var view struct {
		Data operationsTestAPI `json:"data"`
	}
	if e := json.Unmarshal([]byte(body), &view); e != nil {
		t.Fatal(e)
	}
	if res.StatusCode != 200 || view.Data.Revision != 0 || view.Data.Settings.Reports != defaultReportPolicy() {
		t.Fatal("defaults")
	}
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"operations-persistence-save"}}
	next := OperationSettings(view.Data.Settings)
	next.EgressBits = 10_000_000_000
	next.Maintenance = PackMaintenanceConfig{false, 5, 60, 1}
	next.Reports = ReportPolicy{7200, 2, 900}
	next.ReportIntervalMinutes = 25
	raw, _ := json.Marshal(next.editable())
	denied := headers.Clone()
	denied.Set("X-CSRF-Token", "invalid")
	res, _ = client.request("POST", "/api/v1/operations", string(raw), denied)
	if res.StatusCode != 403 {
		t.Fatal("CSRF")
	}
	res, body = client.request("POST", "/api/v1/operations", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, body)
	}
	var expandedSite siteState
	if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &expandedSite); err != nil || expandedSite.MinimumReader != reportIntervalReader {
		t.Fatal("expanded bandwidth reader", err)
	}
	if repo.DeliveryStatus().Budget != 10_000_000_000 || repo.feedCompression.Status().Limit == 0 || repo.feedCompression.Status().Workers < 1 {
		t.Fatal("live limits")
	}
	since := repo.reportSince()
	if since <= 0 {
		t.Fatal("epoch")
	}
	for _, b := range repo.posting {
		snapshot := b.receipt.Load()
		if snapshot == nil {
			t.Fatal("missing guide")
		}
		// 生成した案内を公開DATと同じ文字コードから読み戻す。
		guide, e := textcodec.Decode(snapshot.DAT)
		if e != nil || !strings.Contains(guide, "2時間以内") || !strings.Contains(guide, "2票") || !strings.Contains(guide, "15分停止") {
			t.Fatal("guide conditions", e)
		}
	}
	res, page := client.request("GET", "/operations", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "value=\"120\"") {
		t.Fatal("HTML render")
	}
	res, _ = client.request("POST", "/api/v1/operations", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("retry")
	}
	conflict := headers.Clone()
	conflict.Set("Idempotency-Key", "operations-stale-save")
	res, _ = client.request("POST", "/api/v1/operations", string(raw), conflict)
	if res.StatusCode != 412 {
		t.Fatal("CAS")
	}
	res, body = client.request("GET", "/api/v1/operations", "", nil)
	if e := json.Unmarshal([]byte(body), &view); e != nil {
		t.Fatal(e)
	}
	invalid := next
	invalid.EgressBits = delivery.MaxBudgetBits + 1_000_000
	bad, _ := json.Marshal(invalid.editable())
	conflict.Set("If-Match", res.Header.Get("ETag"))
	res, _ = client.request("POST", "/api/v1/operations", string(bad), conflict)
	if res.StatusCode != 422 {
		t.Fatal("bounds")
	}
	for _, minutes := range []int{-1, 1441} {
		invalid := next
		invalid.ReportIntervalMinutes = minutes
		bad, _ := json.Marshal(invalid.editable())
		res, _ = client.request("POST", "/api/v1/operations", string(bad), conflict)
		if res.StatusCode != 422 {
			t.Fatal("report interval bounds", minutes, res.StatusCode)
		}
	}
	client.server.Close()
	repo.Close()
	repo = nil
	// 起動設定を変えても保存値が優先され、集計の起点は動かない。
	cfg.EgressBits = 80_000_000

	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen", err)
	}
	if repo.operations() != next || repo.reportSince() != since || repo.feedCompression.Status().Workers < 1 || repo.feedCompression.Status().Limit == 0 {
		t.Fatal("saved values")
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	res, page = client.request("GET", "/operations", "", nil)
	fields := pageFields(page)
	fields.Set("egress_mbps", "45")
	fields.Set("maintenance_enabled", "false")
	fields.Set("interval_seconds", "90")
	fields.Set("max_threads", "2")
	fields.Set("max_seconds", "6")
	fields.Set("window_minutes", "120")
	fields.Set("quorum", "2")
	fields.Set("stop_minutes", "15")
	res, body = client.request("POST", "/operations", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("HTML save", res.StatusCode, body)
	}
	if repo.operations().EgressBits != 45_000_000 || repo.reportSince() != since {
		t.Fatal("other settings reset votes")
	}
}
func TestOperationsReportPolicyAndHistoricRule(t *testing.T) {
	p := ReportPolicy{7200, 2, 900}
	at := domain.Time(time.Now().UnixNano())
	votes := []autoReportVote{{Operation: domain.NewID(), Reporter: domain.Hash{1}, IP: domain.Hash{1}, At: at - domain.Time(3*time.Hour)}}
	vote := autoReportVote{Operation: domain.NewID(), Reporter: domain.Hash{2}, IP: domain.Hash{2}, At: at}
	votes, ready := collectAutoReportWithPolicy(votes, vote, p)
	if ready || len(votes) != 1 {
		t.Fatal("window")
	}
	vote.Operation = domain.NewID()
	vote.Reporter = domain.Hash{3}
	vote.IP = domain.Hash{3}
	votes, ready = collectAutoReportWithPolicy(votes, vote, p)
	if !ready || len(votes) != 2 {
		t.Fatal("quorum")
	}
	rule := denialRule{ID: vote.Operation, Scope: denialScope{"board", domain.NewID()}, Reason: "abuse", Effect: denialEffect{Type: "deny"}, Conditions: []denialCondition{{"token", "exact", domain.Hash{4}.String(), "deny"}}, Starts: at, Expires: at + domain.Time(15*time.Minute), Reports: []autoReportEvidenceRef{{votes[0].Operation, autoReportReference{"news", 10, 1}}, {votes[1].Operation, autoReportReference{"news", 10, 1}}}, ReportPolicy: &p}
	if validateAutoReportRefs(rule) != nil {
		t.Fatal("historic validation")
	}
	rule.Expires += domain.Time(time.Minute)
	if validateAutoReportRefs(rule) == nil {
		t.Fatal("historic duration")
	}
	snapshot, e := receiptSnapshotWithPolicy("https://bbs.example", "news", p)
	if e != nil {
		t.Fatal(e)
	}
	guide, e := textcodec.Decode(snapshot.DAT)
	if e != nil || !strings.Contains(guide, "2時間以内") || !strings.Contains(guide, "2票") || !strings.Contains(guide, "15分停止") {
		t.Fatal("guide conditions", e)
	}
	// 表示時間の変換は旧案内と一致し、新しい条件でも整数単位になる。
	if reportDuration(p.WindowSeconds) != "2時間" || reportDuration(p.StopSeconds) != "15分" {
		t.Fatal("guide durations")
	}
}

func TestOperationsReportCommandAndPrivateReceipt(t *testing.T) {
	cfg, repo, site, owner := anonymousFixture(t, "required")
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	if _, e := repo.CreateBoard(t.Context(), "report", "通報"); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.ConfigureAdministrator("owner", "所有者", adminTestSecret, false); e != nil {
		t.Fatal(e)
	}
	repo.Close()
	cfg.AutoReports = &AutoReportConfig{"report", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	save := func(p ReportPolicy) {
		t.Helper()
		res, body := admin.request("GET", "/api/v1/operations", "", nil)
		var view struct {
			Data operationsTestAPI `json:"data"`
		}
		if e := json.Unmarshal([]byte(body), &view); e != nil {
			t.Fatal(e)
		}
		v := OperationSettings(view.Data.Settings)
		v.Reports = p
		raw, _ := json.Marshal(v.editable())
		res, body = admin.request("POST", "/api/v1/operations", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
		if res.StatusCode != 200 {
			t.Fatal("save", res.StatusCode, body)
		}
	}
	policy := ReportPolicy{7200, 2, 900}
	save(policy)
	observer, e := evidence.NewHTTPObserver(site, domain.NewID(), "operations-report-test")
	if e != nil {
		t.Fatal(e)
	}
	public := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
	public.Config.ConnContext = observer.ConnContext
	public.Start()
	defer public.Close()
	victim := newAutoReportHTTPClient(t, public.URL, cfg.Public.BaseURL, "127.125.0.1")
	if body := victim.post(t, "news", "", "TARGET", "operations-target"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("target")
	}
	key := strings.Split(victim.request(t, "/news/subject.txt", nil), ".dat<>")[0]
	first := newAutoReportHTTPClient(t, public.URL, cfg.Public.BaseURL, "127.125.0.2")
	if body := first.post(t, "news", key, ">>1 !report\n理由：荒らし", "operations-command-vote"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("command vote")
	}
	second := newAutoReportHTTPClient(t, public.URL, cfg.Public.BaseURL, "127.125.0.3")
	message := "対象URL：" + cfg.Public.BaseURL + "/test/read.cgi/news/" + key + "/1/\n理由：迷惑投稿"
	if body := second.post(t, "report", "1", message, "operations-private-vote"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("private vote")
	}
	var before denialRule
	repo.mu.Lock()
	_, e = repo.posting[owner].worker.Submit(t.Context(), func() (any, error) {
		if len(repo.posting[owner].denials) != 1 {
			t.Error("quorum not applied")
		}
		for _, entry := range repo.posting[owner].denials {
			before = entry.rule
		}
		return nil, nil
	})
	repo.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if before.ReportPolicy == nil || *before.ReportPolicy != policy || len(before.Reports) != 2 || before.Expires-before.Starts != domain.Time(15*time.Minute) {
		t.Fatal("persisted stop conditions")
	}
	save(defaultReportPolicy())
	if body := victim.post(t, "news", key, "DENIED", "operations-still-stopped"); strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("existing stop lost")
	}
	public.Close()
	admin.server.Close()
	repo.Close()
	repo = nil
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen after policy change", err)
	}
	var after denialRule
	_, e = repo.posting[owner].worker.Submit(t.Context(), func() (any, error) { after = repo.posting[owner].denials[before.ID].rule; return nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	if after.Expires != before.Expires || after.ReportPolicy == nil || *after.ReportPolicy != policy || validateAutoReportRefs(after) != nil {
		t.Fatal("historic stop changed")
	}
}

func TestOperationsFixtureAndReceiptExpiry(t *testing.T) {
	raw, e := os.ReadFile("../../docs/design/fixtures/operation-settings.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Description string              `json:"description"`
		Valid       []OperationSettings `json:"valid"`
		Invalid     []struct {
			Field string `json:"field"`
			Value uint64 `json:"value"`
		} `json:"invalid_overrides"`
	}
	if e = strictjson.Decode(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	for _, v := range fixture.Valid {
		if !v.valid() {
			t.Fatal("valid fixture")
		}
	}
	for _, bad := range fixture.Invalid {
		v := fixture.Valid[0]
		switch bad.Field {
		case "cache_workers":
			v.CacheWorkers = int(bad.Value)
		case "cache_bytes":
			v.CacheBytes = bad.Value
		case "egress_budget_bits_per_second":
			v.EgressBits = bad.Value
		case "quorum":
			v.Reports.Quorum = int(bad.Value)
		case "window_seconds":
			v.Reports.WindowSeconds = int(bad.Value)
		case "stop_seconds":
			v.Reports.StopSeconds = int(bad.Value)
		case "max_seconds":
			v.Maintenance.MaxSeconds = int(bad.Value)
		case "max_threads":
			v.Maintenance.MaxThreads = int(bad.Value)
		case "interval_seconds":
			v.Maintenance.IntervalSeconds = int(bad.Value)
		default:
			t.Fatal("unknown fixture")
		}
		if v.valid() {
			t.Fatal("invalid fixture accepted", bad.Field, bad.Value)
		}
	}
	now := domain.Time(time.Now().UnixNano())
	v := fixture.Valid[0]
	state := operationState{v, now}
	next, _ := json.Marshal(state)
	if e = snapshotSiteValue("operations", "active", nil, next); e != nil {
		t.Fatal("snapshot", e)
	}
	receipt := operationsReceipt{domain.NewID(), domain.NewID(), domain.Hash{1}, domain.Hash{2}, AdminOperations{v, 10, "report"}, now, now + 86400e9}
	value, _ := json.Marshal(receipt)
	rows := store.ControlState{Rows: map[string]store.ControlRow{"operations:active": {Value: next}, "operations_receipt:" + receipt.Key.String(): {Value: value}}}
	names, e := expiredControlNames(rows, 1, receipt.Expires)
	if e != nil || len(names) != 1 {
		t.Fatal("receipt cleanup selection", e)
	}
	if e = validateSiteValue("operations_receipt", receipt.Key.String(), value, json.RawMessage("null")); e != nil {
		t.Fatal("receipt removal", e)
	}
	if e = validateSiteValue("operations", "active", next, json.RawMessage("null")); e == nil {
		t.Fatal("settings removed")
	}
}

// APIの表示用設定は保存形式の過去資源項目を持たないため、保存用の厳密復号器を使わない。
type operationsTestSettings OperationSettings
type operationsTestAPI struct {
	Settings    operationsTestSettings `json:"settings"`
	Revision    domain.U64             `json:"revision"`
	ReportBoard string                 `json:"report_board"`
}
