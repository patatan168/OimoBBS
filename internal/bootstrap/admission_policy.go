// 固定初期規制の永続policyと、主体HMAC・復旧検証を定義する。
package bootstrap

import (
	"bytes"
	"errors"
	"net/netip"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"reflect"
	"sort"
	"sync"
	"time"
)

type refillRatio struct {
	Numerator   domain.U64 `json:"numerator"`
	Denominator domain.U64 `json:"denominator"`
}
type admissionRule struct {
	ID            domain.ID   `json:"id"`
	Kind          string      `json:"kind"`
	Scope         string      `json:"scope"`
	Refill        refillRatio `json:"refill_units_per_second"`
	Burst         uint32      `json:"burst"`
	WindowLimit   uint32      `json:"window_limit"`
	WindowSeconds uint32      `json:"window_seconds"`
}

// AdmissionPolicy は初回有効化で保存する固定の主体・過負荷対策プロファイル。板の間隔条件は別に保存する。秘密鍵を含まない。
type AdmissionPolicy struct {
	Defaults AdminRateSettings `json:"board_rate_defaults"`
	Schema   string            `json:"schema"`
	Revision domain.U64        `json:"revision"`
	Enabled  domain.Time       `json:"enabled_at_ns"`
	KeyID    uint32            `json:"key_id"`
	Rules    []admissionRule   `json:"rules"`
}

func initialAdmission(now time.Time) AdmissionPolicy {
	return AdmissionPolicy{Schema: "admission-v3", Defaults: defaultRateSettings(), Revision: 1, Enabled: domain.Time(now.UnixNano()), KeyID: 7, Rules: []admissionRule{
		{domain.NewID(), "reply", "board", refillRatio{1000000000, 1}, 3, 0, 0},
		{domain.NewID(), "create", "board", refillRatio{1000000000, 600}, 1, 6, 3600},
		{domain.NewID(), "network", "board", refillRatio{60000000000, 1}, 120, 0, 0},
		{domain.NewID(), "site", "site", refillRatio{200000000000, 1}, 400, 0, 0},
	}}
}
func validateAdmission(raw []byte) (AdmissionPolicy, error) {
	var p AdmissionPolicy
	if e := strictjson.Decode(raw, &p); e != nil {
		return p, e
	}
	expected := initialAdmission(time.Unix(0, int64(p.Enabled)))
	if p.Enabled <= 0 || len(p.Rules) != 4 || p.Schema != "admission-v3" {
		return p, abuse.ErrRateSpec
	}
	expected.Defaults.Enabled = p.Defaults.Enabled
	seen := map[domain.ID]bool{}
	for i, r := range p.Rules {
		if r.ID == (domain.ID{}) || seen[r.ID] {
			return p, abuse.ErrRateSpec
		}
		seen[r.ID] = true
		expected.Rules[i].ID = r.ID
	}
	if !reflect.DeepEqual(p, expected) {
		return p, abuse.ErrRateSpec
	}
	return p, nil
}

type admission struct {
	globalRates         *AdminRateSettings
	mandatoryCookieFrom domain.Time
	mu                  sync.Mutex
	policy              AdmissionPolicy
	anonymous           *AnonymousPolicy
	secret              domain.Hash
	limits              *abuse.Limiter
	lastPrune           time.Time
	lastReserved        domain.Time
	lastAttempt         domain.Time
	boardRates          map[domain.ID]AdminRateSettings
	boardKeys           map[domain.ID]map[string]bool
	overrides           map[domain.ID]map[domain.ID]denialRule
}

func (a *admission) charges(board domain.ID, ip netip.Addr, create bool) ([]abuse.RateCharge, []domain.RateKey) {
	ip = ip.Unmap()
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	network := netip.PrefixFrom(ip, bits).Masked().String()
	type item struct {
		charge abuse.RateCharge
		key    domain.RateKey
	}
	items := []item{}
	for _, r := range a.policy.Rules {
		if r.Kind == "reply" && create || r.Kind == "create" && !create {
			continue
		}
		scope, kind, value := board[:], "ip", []byte(ip.String())
		if r.Kind == "network" {
			kind, value = "network", []byte(network)
		}
		if r.Kind == "site" {
			scope, kind, value = []byte("site"), "site", []byte{}
		}
		h := identity.MAC(a.secret[:], "oimo/rate/v1", r.ID[:], scope, []byte(kind), value)
		spec := abuse.RateSpec{Tokens: uint64(r.Refill.Numerator) / 1000000000, Every: time.Duration(r.Refill.Denominator) * time.Second, Burst: r.Burst, WindowLimit: r.WindowLimit}
		if r.Kind == "reply" || r.Kind == "create" {
			v := a.ratesForBoard(board)
			spec = v.spec(create)
		}
		items = append(items, item{abuse.RateCharge{Key: r.ID.String() + ":" + h.String(), Spec: spec, Cost: 1}, domain.RateKey{Rule: r.ID, KeyID: 7, Subject: h, Cost: 1}})
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].key.Rule[:], items[j].key.Rule[:]) < 0 })
	charges := make([]abuse.RateCharge, 0, len(items))
	keys := make([]domain.RateKey, 0, len(items))
	for _, v := range items {
		charges = append(charges, v.charge)
		keys = append(keys, v.key)
	}
	return charges, keys
}
func (a *admission) validate(board domain.ID, r app.RateRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mandatoryCookieFrom != 0 && r.At >= a.mandatoryCookieFrom && r.TokenStatus != "valid" {
		return errors.New("required slip cookie absent from accepted record")
	}
	if r.At < a.policy.Enabled {
		if len(r.Keys) != 0 {
			return errors.New("rate keys before activation")
		}
		return nil
	}
	if e := a.validateOverridesLocked(board, &r); e != nil {
		return e
	}
	if a.anonymous != nil && r.At >= a.anonymous.Enabled {
		if a.anonymous.modeAt(r.At) == "required" && r.TokenStatus != "valid" {
			return errors.New("required token absent from accepted record")
		}
		if r.Schema != postcapture.Schema {
			return errors.New("missing anonymous capture")
		}
		if r.TokenStatus == "valid" {
			if r.Token == nil || len(r.Keys) != 4 {
				return errors.New("missing token rate proof")
			}
			rule := a.anonymous.ReplyRule
			if r.Create {
				rule = a.anonymous.CreateRule
			}
			if r.Token.Rate.Rule != rule {
				return errors.New("token rule mismatch")
			}
			found := false
			for _, key := range r.Keys {
				if key == r.Token.Rate {
					found = true
				}
			}
			if !found {
				return errors.New("token proof mismatch")
			}
		} else if r.Token != nil || len(r.Keys) != 3 || (r.TokenStatus != "absent" && r.TokenStatus != "invalid") {
			return errors.New("invalid token status")
		}
	} else if r.TokenStatus != "" && r.TokenStatus != "not_checked" || r.Token != nil {
		return errors.New("anonymous capture before activation")
	}
	for i := 1; i < len(r.Keys); i++ {
		if bytes.Compare(r.Keys[i-1].Rule[:], r.Keys[i].Rule[:]) >= 0 {
			return errors.New("noncanonical rate keys")
		}
	}
	ip, e := netip.ParseAddr(r.IP)
	if e != nil || ip.Zone() != "" {
		return abuse.ErrRateSpec
	}
	_, want := a.charges(board, ip, r.Create)
	actual := r.Keys
	if a.anonymous != nil && r.At >= a.anonymous.Enabled && len(actual) == 4 {
		rule := a.anonymous.ReplyRule
		if r.Create {
			rule = a.anonymous.CreateRule
		}
		filtered := make([]domain.RateKey, 0, 3)
		found := false
		for _, key := range actual {
			if key.Rule == rule && key.KeyID == 7 && key.Cost == 1 && key.Subject != (domain.Hash{}) && !found {
				found = true
				continue
			}
			filtered = append(filtered, key)
		}
		if !found {
			return errors.New("invalid token rate key")
		}
		actual = filtered
	}
	if !reflect.DeepEqual(want, actual) {
		return errors.New("posting rate keys mismatch")
	}

	return nil
}
func (a *admission) reserve(board domain.ID, ip netip.Addr, create bool, clock func() time.Time) (*abuse.RateTicket, []domain.RateKey, time.Time, error) {
	return a.reserveAnonymous(board, ip, create, clock, domain.ID{})
}
func (a *admission) reserveAnonymous(board domain.ID, ip netip.Addr, create bool, clock func() time.Time, token domain.ID) (*abuse.RateTicket, []domain.RateKey, time.Time, error) {
	return a.reserveOverrides(board, ip, create, clock, token, nil)
}

func (a *admission) reserveOverrides(board domain.ID, ip netip.Addr, create bool, clock func() time.Time, token domain.ID, ids []domain.ID) (*abuse.RateTicket, []domain.RateKey, time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := clock()
	if domain.Time(now.UnixNano()) < max(a.policy.Enabled, a.lastReserved) {
		return nil, nil, now, abuse.ErrRateClock
	}
	if a.lastPrune.IsZero() || now.Sub(a.lastPrune) >= time.Minute {
		a.limits.Prune(now)
		a.pruneBoardKeys()
		a.lastPrune = now
	}
	a.lastReserved = domain.Time(now.UnixNano())
	charges, keys := a.charges(board, ip, create)
	if token != (domain.ID{}) {
		if a.anonymous == nil {
			return nil, nil, now, abuse.ErrToken
		}
		c, k := a.tokenChargeLocked(board, token, create)
		charges = append(charges, c)
		keys = append(keys, k)
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i].Rule[:], keys[j].Rule[:]) < 0 })
	}
	for _, id := range ids {
		rule, ok := a.overrides[board][id]
		if !ok || !rule.Enabled || domain.Time(now.UnixNano()) < rule.Starts || domain.Time(now.UnixNano()) >= rule.Expires {
			return nil, nil, now, abuse.ErrRateClock
		}
		c, k := a.overrideCharge(board, ip, rule)
		charges = append(charges, c)
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i].Rule[:], keys[j].Rule[:]) < 0 })
	ticket, e := a.limits.Reserve(now, charges)
	if e == nil {
		a.trackBoardCharges(board, create, charges)
	}
	return ticket, keys, now, e
}

func parseRateIP(raw string) (netip.Addr, error) {
	ip, e := netip.ParseAddr(raw)
	if e != nil || ip.Zone() != "" {
		return netip.Addr{}, abuse.ErrRateSpec
	}
	return ip.Unmap(), nil
}

// tokenCharge は検証済みのIDだけを追加枠に使う。IP/network/siteの枠は維持する。
func (a *admission) tokenCharge(board, token domain.ID, create bool) (abuse.RateCharge, domain.RateKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokenChargeLocked(board, token, create)
}
func (a *admission) tokenChargeLocked(board, token domain.ID, create bool) (abuse.RateCharge, domain.RateKey) {
	rule := a.anonymous.ReplyRule
	v := a.ratesForBoard(board)
	spec := v.spec(create)
	if create {
		rule = a.anonymous.CreateRule
	}
	h := identity.MAC(a.secret[:], "oimo/rate/v1", rule[:], board[:], []byte("token"), token[:])
	return abuse.RateCharge{Key: rule.String() + ":" + h.String(), Spec: spec, Cost: 1}, domain.RateKey{Rule: rule, KeyID: 7, Subject: h, Cost: 1}
}
