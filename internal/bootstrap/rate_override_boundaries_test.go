// 追加枠の上限・旧形式・時計・条件除外と、保存capture改変の拒否を検査する。
package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
	"oimobbs/internal/strictjson"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRateOverrideHTMLAndCapacity(t *testing.T) {
	_, r, board := anonymousAdminFixture(t, "required")
	defer r.Close()
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/boards/" + board.String() + "/rules"
	for i := range 13 {
		_, body := c.request("GET", path, "", nil)
		fields := pageFields(strings.Split(body, "</form>")[0])
		fields.Set("field", "body")
		fields.Set("operator", "contains")
		fields.Set("target", "追加")
		fields.Set("effect", "rate_override")
		fields.Set("operation", "reply")
		fields.Set("duration_minutes", "60")
		fields.Set("reason_code", "spam")
		fields.Set("refill_seconds", "3600")
		fields.Set("burst", "1")
		fields.Set("window_limit", "1")
		res, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		want := 303
		if i == 12 {
			want = 503
		}
		if res.StatusCode != want {
			t.Fatal("HTML capacity", i, res.StatusCode, body)
		}
		if i == 0 {
			res, _ = c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
			if res.StatusCode != 303 {
				t.Fatal("fixed replay")
			}
		}
	}
	_, list := c.rules(board)
	if len(list.Rules) != 12 || list.Rules[0].Rate == nil {
		t.Fatal("capacity saved")
	}
	if e := validateOverrideHistory(r.posting[board].denials); e != nil {
		t.Fatal(e)
	}
	server, request, _ := anonymousHTTP(t, r, siteID(r.site.State()))
	defer server.Close()
	post := url.Values{"bbs": {"news"}, "subject": {"16枠確認"}, "MESSAGE": {"最初"}, "oimo_request_id": {"rate-max-create-request-001"}}
	request("POST", "/test/bbs.cgi", post)
	request("POST", "/test/bbs.cgi", post)
	rows, _ := r.rateHistory()
	if len(rows) != 1 {
		t.Fatal("max create")
	}
	post.Del("subject")
	post.Set("key", strconv.FormatUint(rows[0].key, 10))
	post.Set("MESSAGE", "追加")
	post.Set("oimo_request_id", "rate-max-reply-request-001")
	request("POST", "/test/bbs.cgi", post)
	_, body := request("POST", "/test/bbs.cgi", post)
	rows, _ = r.rateHistory()
	if len(rows) != 2 || len(rows[1].record.Keys) != 16 || len(rows[1].record.Overrides) != 12 {
		t.Fatal("16 keys rejected", body)
	}
	checkRateCaptureTampering(t, r.posting[board])
}

func TestRateOverrideNeedsAdmission(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, e := r.CreateBoard(t.Context(), "rate", "追加枠")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := c.rules(board.ID)
	input := AdminRuleInput{Target: "追加", Operations: []string{"reply"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"body", "contains", "rate_override"}, Rate: &AdminRateOverride{10, 1, 0}}
	raw, _ := json.Marshal(input)
	res, _ = c.request("POST", "/api/v1/boards/"+board.ID.String()+"/rules", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 422 || len(r.posting[board.ID].denials) != 0 {
		t.Fatal("unmetered rate accepted")
	}
}

func TestRateOverrideHistoryAndClock(t *testing.T) {
	now := time.Now()
	a := &admission{policy: initialAdmission(now), limits: abuse.NewLimiter(100), secret: domain.Hash{1}, boardRates: map[domain.ID]AdminRateSettings{}, boardKeys: map[domain.ID]map[string]bool{}}
	board := domain.NewID()
	at := domain.Time(now.Add(time.Second).UnixNano())
	rate := denialRule{ID: domain.NewID(), Revision: 1, Scope: denialScope{"board", board}, Operations: []string{"reply"}, Conditions: []denialCondition{{"body", "contains", "追加", "deny"}}, Effect: denialEffect{Type: "rate_override", Rate: &AdminRateOverride{3600, 1, 1}}, Starts: at, Expires: at + domain.Time(time.Hour), Reason: "spam", Enabled: true}
	compiled, _ := compileDenial(rate)
	b := &postingBoard{owner: board, admission: a, denials: map[domain.ID]compiledDenial{rate.ID: compiled}}
	a.installOverrides(board, b.denials)
	ip := netip.MustParseAddr("192.0.2.1")
	ticket, keys, clock, e := a.reserveOverrides(board, ip, false, func() time.Time { return now.Add(2 * time.Second) }, domain.ID{}, []domain.ID{rate.ID})
	if e != nil || a.limits.Commit(ticket) != nil {
		t.Fatal(e)
	}
	record := app.RateRecord{Schema: postcapture.Schema, TokenStatus: "not_checked", ID: domain.NewID(), At: domain.Time(clock.UnixNano()), IP: ip.String(), Keys: keys, Overrides: []domain.ID{rate.ID}}
	if e = a.validate(board, record); e != nil {
		t.Fatal("valid key", e)
	}
	for _, mutate := range []func(*app.RateRecord){func(r *app.RateRecord) { r.Overrides = nil }, func(r *app.RateRecord) { r.IP = "192.0.2.2" }, func(r *app.RateRecord) { r.Overrides = []domain.ID{domain.NewID()} }, func(r *app.RateRecord) { r.Schema = "http-observation-v4" }} {
		bad := record
		mutate(&bad)
		if a.validate(board, bad) == nil {
			t.Fatal("rate proof bypass")
		}
	}
	if b.checkRuleClock(record.At) == nil {
		t.Fatal("retroactive activation")
	}
	if b.checkRuleClock(record.At+1) != nil {
		t.Fatal("valid activation")
	}
	stopped := record.At + 1
	rate.Enabled = false
	rate.Revision = 2
	rate.Effect.Stopped = &stopped
	compiled, e = compileDenial(rate)
	if e != nil {
		t.Fatal(e)
	}
	b.denials[rate.ID] = compiled
	a.installOverrides(board, b.denials)
	if e = a.validate(board, record); e != nil {
		t.Fatal("old proof lost", e)
	}
	record.At = stopped
	if a.validate(board, record) == nil {
		t.Fatal("post-revoke proof")
	}
	matched, e := b.matchedRules(ip, postinput.Input{Body: "追加"}, domain.Hash{}, false, stopped-1, nil, true)
	if e != nil || len(matchedOverrides(matched)) != 1 {
		t.Fatal("history lost", e)
	}
}

func checkRateCaptureTampering(t *testing.T, b *postingBoard) {
	t.Helper()
	found := false
	for _, journal := range b.journals {
		for _, entry := range journal.Entries() {
			if entry.Event.Kind != "evidence_proposal" {
				continue
			}
			var proposal struct {
				Capture json.RawMessage `json:"capture"`
				Frame   string          `json:"prepared_frame_base64"`
				Key     domain.U64      `json:"thread_key"`
			}
			if json.Unmarshal(entry.Payload, &proposal) != nil {
				t.Fatal("proposal")
			}
			var fields map[string]json.RawMessage
			json.Unmarshal(proposal.Capture, &fields)
			if string(fields["schema"]) != strconv.Quote(postcapture.Schema) {
				continue
			}
			found = true
			frame, _ := base64.StdEncoding.DecodeString(proposal.Frame)
			if e := postcapture.ValidateFrame(proposal.Capture, frame, uint64(proposal.Key)); e != nil {
				t.Fatal(e)
			}
			for _, field := range []string{"overrides", "cap", "token"} {
				bad := make(map[string]json.RawMessage)
				for k, v := range fields {
					if k != field {
						bad[k] = v
					}
				}
				raw, _ := json.Marshal(bad)
				if postcapture.Validate(raw) == nil {
					t.Fatal("missing proof", field)
				}
			}
			fields["overrides"], _ = json.Marshal([]domain.ID{domain.NewID()})
			raw, _ := json.Marshal(fields)
			if postcapture.ValidateFrame(raw, frame, uint64(proposal.Key)) == nil || b.validateOverrideCapture(raw) == nil {
				t.Fatal("tampered extra ID")
			}
		}
	}
	if !found {
		t.Fatal("missing current capture")
	}
}

func TestRateOverrideEffectCodec(t *testing.T) {
	for _, raw := range []string{`{"type":"rate_override","ids":[],"rate":{"refill_seconds":1,"burst":1,"window_limit":0},"revoked_at_ns":null}`, `{"type":"deny","ids":[],"rate":null,"revoked_at_ns":null}`, `{"type":"require_token","ids":[],"rate":null,"revoked_at_ns":null}`} {
		var effect denialEffect
		if e := strictjson.Decode([]byte(raw), &effect); e != nil || !validRuleEffect(effect) {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{`{"type":"deny","rate":{"refill_seconds":1,"burst":1,"window_limit":0}}`, `{"type":"rate_override","rate":null}`, `{"type":"deny","revoked_at_ns":null}`} {
		var effect denialEffect
		if strictjson.Decode([]byte(raw), &effect) == nil {
			t.Fatal("invalid union", raw)
		}
	}
}

func TestRateOverrideFixture(t *testing.T) {
	raw, err := os.ReadFile("../../docs/design/fixtures/rate-overrides.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema string `json:"schema"`
		Cases  []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"cases"`
	}
	if err = strictjson.Decode(raw, &fixture); err != nil || fixture.Schema != "rate-overrides-v1" {
		t.Fatal(err)
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			var value AdminRateOverride
			err := strictjson.Decode(item.Value, &value)
			if (err == nil && value.valid()) != item.Valid {
				t.Fatal("fixture", err)
			}
		})
	}
}
