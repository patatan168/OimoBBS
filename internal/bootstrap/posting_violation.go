// 攻撃固有の指定規制への反復違反を、IPを含めずCookie主体の期限付き停止へ接続する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const violationLimit = 5
const violationWindow = domain.Time(60e9)
const violationStop = domain.Time(600e9)
const violationSubjects = 4096

// ErrRepeatedViolation は反復した指定規制違反によるCookie主体の一時投稿停止。
var ErrRepeatedViolation = errors.New("repeated targeted spam violation")

type violationState struct {
	Subject  domain.Hash   `json:"subject_hmac"`
	Requests []domain.Hash `json:"requests_hmac"`
	Started  domain.Time   `json:"started_at_ns"`
	Updated  domain.Time   `json:"updated_at_ns"`
	Expires  domain.Time   `json:"expires_at_ns"`
	Blocked  bool          `json:"blocked"`
}
type violationCandidate struct {
	subject, request domain.Hash
	at               domain.Time
}

// targetedSpamViolation は許可で除外されていない、管理者指定の長文・URL規制だけを選ぶ。
func targetedSpamViolation(matched map[domain.ID]denialRule) bool {
	excluded := excludedRules(matched)
	for id, rule := range matched {
		if excluded[id] || rule.Effect.Type != "deny" || rule.Reason != "spam" || rule.ReportPolicy != nil {
			continue
		}
		for _, c := range rule.Conditions {
			if c.Field == "domain" || c.Field == "body" && (c.Operator == "exact" || c.Operator == "contains") && utf8.RuneCountInString(strings.TrimSpace(c.Value)) >= 12 {
				return true
			}
		}
	}
	return false
}

// violationRequest はIP変更に影響されない要求・内容のHMAC。明示IDがない同内容の再送も一件にする。
func violationRequest(key domain.Hash, subject domain.Hash, d domain.Dedup) domain.Hash {
	id := []byte{}
	if d.RequestID != nil {
		id = d.RequestID[:]
	}
	return identity.MAC(key[:], "oimo/targeted-violation-request/v1", subject[:], d.Request[:], id)
}

// nextViolation は固定60秒窓の異なる要求だけを数え、5件目から600秒の停止へ遷移する。
func nextViolation(prior violationState, c violationCandidate) (violationState, bool, error) {
	if c.subject == (domain.Hash{}) || c.request == (domain.Hash{}) || c.at <= 0 || c.at > domain.Time(1<<63-1)-violationStop {
		return prior, false, store.ErrCorrupt
	}
	if prior.Subject != (domain.Hash{}) && c.at < prior.Updated {
		return prior, false, abuse.ErrRateClock
	}
	if prior.Subject == (domain.Hash{}) || c.at >= prior.Expires {
		prior = violationState{Subject: c.subject, Requests: []domain.Hash{}, Started: c.at, Updated: c.at, Expires: c.at + violationWindow}
	}
	if prior.Subject != c.subject {
		return prior, false, store.ErrCorrupt
	}
	if prior.Blocked {
		return prior, false, nil
	}
	for _, old := range prior.Requests {
		if old == c.request {
			return prior, false, nil
		}
	}
	prior.Requests = append(append([]domain.Hash{}, prior.Requests...), c.request)
	prior.Updated = c.at
	if len(prior.Requests) == violationLimit {
		prior.Blocked = true
		prior.Expires = c.at + violationStop
	}
	return prior, true, nil
}

// validateViolationValue は全項目必須・上限・時刻・再送集合と停止遷移を検査する。
func validateViolationValue(key string, old, next json.RawMessage) error {
	var v violationState
	if strictjson.Decode(next, &v) != nil || key != v.Subject.String() || v.Subject == (domain.Hash{}) || len(v.Requests) < 1 || len(v.Requests) > violationLimit || v.Started <= 0 || v.Updated < v.Started || v.Updated >= v.Started+violationWindow || v.Updated > domain.Time(1<<63-1)-violationStop {
		return store.ErrCorrupt
	}
	seen := map[domain.Hash]bool{}
	for _, h := range v.Requests {
		if h == (domain.Hash{}) || seen[h] {
			return store.ErrCorrupt
		}
		seen[h] = true
	}
	if v.Blocked != (len(v.Requests) == violationLimit) || !v.Blocked && v.Expires != v.Started+violationWindow || v.Blocked && v.Expires != v.Updated+violationStop {
		return store.ErrCorrupt
	}
	if len(old) > 0 {
		var p violationState
		if strictjson.Decode(old, &p) != nil || v.Updated < p.Updated {
			return store.ErrCorrupt
		}
		expected, changed, err := nextViolation(p, violationCandidate{v.Subject, v.Requests[len(v.Requests)-1], v.Updated})
		if err != nil || !changed || !reflect.DeepEqual(expected, v) {
			return store.ErrCorrupt
		}
	}
	return nil
}

// repeatedViolationWait は板所有列から短い共通mutexだけで停止を読む。受理済み再送の照会後に使う。
func (b *postingBoard) repeatedViolationWait(subject domain.Hash, now domain.Time) error {
	if b.guard == nil || subject == (domain.Hash{}) {
		return nil
	}
	b.guard.mu.Lock()
	defer b.guard.mu.Unlock()
	v := b.guard.violations[subject]
	if now < v.Updated {
		// 板列で採時した後に別板の記録が先に公開されることがある。
		now = domain.Time(time.Now().UnixNano())
		if now < v.Updated {
			return abuse.ErrRateClock
		}
	}
	if v.Blocked && now < v.Expires {
		return fmt.Errorf("%w: %w", ErrRepeatedViolation, &abuse.RateLimited{RetryAfter: uint64((v.Expires - now + 1e9 - 1) / 1e9)})
	}
	return nil
}

// recordViolation は板所有列を離れた後に耐久保存し、保存できた停止だけを全板へ公開する。
func (r *Repository) recordViolation(c violationCandidate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return err
	}
	g := r.guard
	g.mu.Lock()
	defer g.mu.Unlock()
	// 複数板の観測順と保存順は一致しないため、直列保存の取得時刻で窓を数える。
	c.at = domain.Time(time.Now().UnixNano())
	if c.at < domain.Time(r.controlExpiryFloor.Load()) {
		return ErrControlExpiryClock
	}
	if g.violations == nil {
		g.violations = map[domain.Hash]violationState{}
	}
	state := r.site.State()
	var prior violationState
	row := state.Rows["posting_violation:"+c.subject.String()]
	if len(row.Value) > 0 && strictjson.Decode(row.Value, &prior) != nil {
		return store.ErrCorrupt
	}
	next, changed, err := nextViolation(prior, c)
	if err != nil || !changed {
		return err
	}
	names := []string{}
	total := 0
	for name, entry := range state.Rows {
		if !strings.HasPrefix(name, "posting_violation:") {
			continue
		}
		total++
		if name == "posting_violation:"+c.subject.String() {
			continue
		}
		var v violationState
		if strictjson.Decode(entry.Value, &v) != nil {
			return store.ErrCorrupt
		}
		if v.Expires <= c.at {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	names = names[:min(len(names), 128)]
	if len(row.Value) == 0 && total-len(names) >= violationSubjects {
		return abuse.ErrRateCapacity
	}
	if len(names) > 0 {
		clean := []store.Mutation{}
		for _, name := range names {
			entry := state.Rows[name]
			clean = append(clean, store.Mutation{Collection: "posting_violation", Key: strings.TrimPrefix(name, "posting_violation:"), ExpectedRevision: entry.Revision, Value: json.RawMessage("null")})
		}
		if int64(c.at) > r.controlExpiryFloor.Load() {
			clean = append(clean, mutation("expiry_watermark", "control", controlExpiryWatermark{c.at}, nil))
		}
		if err = appendControlAt(r.site, c.at, "expired_records_cleanup", clean); err != nil {
			r.stopped = true
			return err
		}
		r.controlExpiryFloor.Store(int64(c.at))
		state = r.site.State()
	}
	var site siteState
	if strictjson.Decode(state.Rows["site:state"].Value, &site) != nil {
		return store.ErrCorrupt
	}
	changes := []store.Mutation{}
	if site.MinimumReader < 80 {
		site.MinimumReader = 80
		changes = append(changes, mutation("site", "state", site, nil))
	}

	changes = append(changes, mutation("posting_violation", c.subject.String(), next, nil))
	if err = appendControl(r.site, "targeted_spam_violation", changes, []string{}); err != nil {
		r.stopped = true
		return err
	}
	for subject, v := range g.violations {
		if v.Expires <= c.at {
			delete(g.violations, subject)
		}
	}
	g.violations[c.subject] = next
	return nil
}

// restoreViolations はsnapshot/backup/restartとも同じ厳密検査を通したCookie履歴だけを復旧する。
func (r *Repository) restoreViolations() error {
	state := r.site.State()
	var site siteState
	if strictjson.Decode(state.Rows["site:state"].Value, &site) != nil {
		return store.ErrCorrupt
	}
	values, err := inspectViolations(state, site)
	if err != nil {
		return err
	}
	r.guard.mu.Lock()
	defer r.guard.mu.Unlock()
	r.guard.violations = values
	return nil
}

// inspectViolations は保存状態のreader境界・期限・件数を復旧前に検査する。
func inspectViolations(state store.ControlState, site siteState) (map[domain.Hash]violationState, error) {
	values := map[domain.Hash]violationState{}
	now := domain.Time(time.Now().UnixNano())
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "posting_violation:") {
			continue
		}
		var v violationState
		if site.MinimumReader < 80 || row.Expires != nil || validateViolationValue(strings.TrimPrefix(name, "posting_violation:"), nil, row.Value) != nil || strictjson.Decode(row.Value, &v) != nil || v.Updated > now {
			return nil, store.ErrCorrupt
		}
		values[v.Subject] = v
	}
	if len(values) > violationSubjects {
		return nil, store.ErrCorrupt
	}
	return values, nil
}
