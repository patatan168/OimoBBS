// 反復違反の再送除外・期限・保存復旧と、巻き込まない指定規制の境界を検証する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/textcodec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRepeatedViolationWindowRetryAndExpiry(t *testing.T) {
	at := domain.Time(100e9)
	subject := domain.Hash{1}
	var v violationState
	for i := 1; i <= violationLimit; i++ {
		candidate := violationCandidate{subject, domain.Hash{byte(i)}, at + domain.Time(i)}
		next, changed, err := nextViolation(v, candidate)
		if err != nil || !changed {
			t.Fatal(next, changed, err)
		}
		v = next
		retry, changed, err := nextViolation(v, candidate)
		if err != nil || changed || !reflect.DeepEqual(v, retry) {
			t.Fatal("retry counted", err)
		}
	}
	if !v.Blocked || v.Expires != v.Updated+violationStop {
		t.Fatal(v)
	}
	next, changed, err := nextViolation(v, violationCandidate{subject, domain.Hash{99}, v.Updated + 1})
	if err != nil || changed || !reflect.DeepEqual(v, next) {
		t.Fatal("stop extended", err)
	}
	next, changed, err = nextViolation(v, violationCandidate{subject, domain.Hash{99}, v.Expires})
	if err != nil || !changed || next.Blocked || len(next.Requests) != 1 {
		t.Fatal("expiry boundary", next, err)
	}
	if _, _, err = nextViolation(v, violationCandidate{subject, domain.Hash{99}, v.Updated - 1}); !errors.Is(err, abuse.ErrRateClock) {
		t.Fatal("clock", err)
	}
	next, _, _ = nextViolation(violationState{}, violationCandidate{subject, domain.Hash{1}, at})
	next, _, _ = nextViolation(next, violationCandidate{subject, domain.Hash{2}, at + violationWindow})
	if len(next.Requests) != 1 {
		t.Fatal("window was sliding", next)
	}
}

func TestRepeatedViolationOnlyTargetedSpam(t *testing.T) {
	id := domain.NewID()
	good := denialRule{ID: id, Reason: "spam", Conditions: []denialCondition{{Field: "body", Operator: "contains", Value: "攻撃に固有の長い広告文章を指定する"}}, Effect: denialEffect{Type: "deny"}}
	for _, tc := range []struct {
		name, reason, field, operator, value string
		want                                 bool
	}{
		{"long", "spam", "body", "contains", "攻撃に固有の長い広告文章を指定する", true},
		{"domain", "spam", "domain", "suffix", "spam.example", true},
		{"short", "spam", "body", "exact", "草", false},
		{"ip", "spam", "ip", "exact", "192.0.2.1", false},
		{"rate", "spam", "body", "regexp", "広告.*", false},
		{"nonspam", "other", "body", "contains", "攻撃に固有の長い広告文章を指定する", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := good
			v.Reason = tc.reason
			v.Conditions = []denialCondition{{Field: tc.field, Operator: tc.operator, Value: tc.value}}
			if got := targetedSpamViolation(map[domain.ID]denialRule{id: v}); got != tc.want {
				t.Fatal(got)
			}
		})
	}
	allowID := domain.NewID()
	if targetedSpamViolation(map[domain.ID]denialRule{id: good, allowID: {ID: allowID, Effect: denialEffect{Type: "allow_rule_ids", IDs: []domain.ID{id}}}}) {
		t.Fatal("allowed rule counted")
	}
	good.ReportPolicy = &ReportPolicy{}
	if targetedSpamViolation(map[domain.ID]denialRule{id: good}) {
		t.Fatal("automatic reports counted")
	}
}

func TestRepeatedViolationStrictState(t *testing.T) {
	v, _, _ := nextViolation(violationState{}, violationCandidate{domain.Hash{1}, domain.Hash{2}, domain.Time(100e9)})
	raw, _ := json.Marshal(v)
	if err := validateViolationValue(v.Subject.String(), nil, raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{}`, strings.Replace(string(raw), `"blocked":false`, `"blocked":null`, 1), strings.Replace(string(raw), `"blocked":false`, `"blocked":false,"blocked":false`, 1), strings.Replace(string(raw), `"blocked":false`, `"blocked":false,"extra":1`, 1)} {
		if validateViolationValue(v.Subject.String(), nil, []byte(bad)) == nil {
			t.Fatal("accepted invalid", bad)
		}
	}
	next, _, _ := nextViolation(v, violationCandidate{v.Subject, domain.Hash{3}, v.Updated + 1})
	nextRaw, _ := json.Marshal(next)
	if err := validateViolationValue(v.Subject.String(), raw, nextRaw); err != nil {
		t.Fatal(err)
	}
	next.Requests[0] = domain.Hash{9}
	nextRaw, _ = json.Marshal(next)
	if validateViolationValue(v.Subject.String(), raw, nextRaw) == nil {
		t.Fatal("changed prior request")
	}
}

func TestRepeatedViolationPersistenceRestartAndSharedSubject(t *testing.T) {
	cfg, repo, _, owner := anonymousFixture(t, "required")
	defer func() { repo.Close() }()
	// CLI指定規制はWeb管理者未設定でも使うため、その保存状態で検証する。
	subject := domain.Hash{1}
	at := domain.Time(time.Now().Add(-time.Second).UnixNano())
	for i := 1; i <= 5; i++ {
		// 別板の観測順と保存順が逆でも、保存時刻で集計する。
		if err := repo.recordViolation(violationCandidate{subject, domain.Hash{byte(i)}, at - domain.Time(i)}); err != nil {
			t.Fatal(err)
		}
	}
	b := repo.posting[owner]
	at = repo.guard.violations[subject].Updated
	var limited *abuse.RateLimited
	if err := b.repeatedViolationWait(subject, at+10); !errors.Is(err, ErrRepeatedViolation) || !errors.As(err, &limited) || limited.RetryAfter != 600 {
		t.Fatal(err)
	}
	if err := b.repeatedViolationWait(domain.Hash{2}, at+10); err != nil {
		t.Fatal("another Cookie on shared IP stopped", err)
	}
	if err := b.repeatedViolationWait(subject, at+violationStop); err != nil {
		t.Fatal("expired", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.posting[owner].repeatedViolationWait(subject, domain.Time(time.Now().UnixNano())); !errors.Is(err, ErrRepeatedViolation) {
		t.Fatal("restart forgot", err)
	}
	state := repo.site.State()
	var site siteState
	json.Unmarshal(state.Rows["site:state"].Value, &site)
	site.MinimumReader = 79
	if _, err := inspectViolations(state, site); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("old reader accepted", err)
	}
	if _, err = repo.ConfigureAdministrator("owner", "管理者", adminTestSecret, false); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.EnableControlSnapshots(t.Context()); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(candidateParent(t), "violation-candidate")
	if _, err = repo.PrepareControlSnapshot(t.Context(), candidate, 6); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ActivateControlSnapshot(t.Context(), cfg, candidate, postcapture.Validate); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.posting[owner].repeatedViolationWait(subject, domain.Time(time.Now().UnixNano())); !errors.Is(err, ErrRepeatedViolation) {
		t.Fatal("snapshot forgot", err)
	}
}

// TestRepeatedViolationPublicReasonHidden はWeb・専ブラとも停止主体と判定理由を公開しないことを確認する。
func TestRepeatedViolationPublicReasonHidden(t *testing.T) {
	_, repo, site, _ := anonymousFixture(t, "required")
	defer repo.Close()
	now := time.Now()
	cookie, err := repo.anonymousCookie("", netip.MustParseAddr("127.0.0.1"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	token, err := repo.anonymous.verify(cookie.Value, now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= violationLimit; i++ {
		if err := repo.recordViolation(violationCandidate{repo.anonymous.subject(token.ID), domain.Hash{byte(i)}, domain.Time(now.UnixNano())}); err != nil {
			t.Fatal(err)
		}
	}
	server, request, cookies := anonymousHTTP(t, repo, site)
	defer server.Close()
	cookies["oimo_anon"] = cookie
	for _, route := range []string{"/web/post?bbs=news", "/test/bbs.cgi"} {
		fields := url.Values{"bbs": {"news"}, "subject": {"非公開理由試験"}, "MESSAGE": {"PUBLIC-GENERIC-LIMIT"}}
		if strings.HasPrefix(route, "/web/") {
			_, page := request("GET", route, nil)
			fields = pageFields(page)
			fields.Set("subject", "非公開理由試験")
			fields.Set("MESSAGE", "PUBLIC-GENERIC-LIMIT")
		}
		response, body := request("POST", route, fields)
		if response.StatusCode == 200 {
			if strings.HasPrefix(route, "/web/") {
				fields = pageFields(body)
			}
			response, body = request("POST", route, fields)
		}
		if route == "/test/bbs.cgi" {
			body, err = textcodec.Decode([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
		}
		if response.StatusCode != 429 || response.Header.Get("Retry-After") == "" || !strings.Contains(body, "投稿間隔を空けて") {
			t.Fatal(route, response.StatusCode, body)
		}
		for _, word := range []string{"反復違反", "匿名Cookie", "再発行", "埋め立て対策"} {
			if strings.Contains(body, word) {
				t.Fatal("public reason", route, word)
			}
		}
	}
}
