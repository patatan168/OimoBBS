// 管理者の規制登録・解除を、認可・CAS・永続再送・板内直列保存へ接続する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"strings"
	"time"
)

// AdminRuleInput は板拒否規制の初回登録値。期限は初回保存時からの分数で固定する。
type AdminRuleInput struct {
	Target     string               `json:"target"`
	Operations []string             `json:"operations"`
	Minutes    uint32               `json:"duration_minutes"`
	Reason     string               `json:"reason_code"`
	Match      *AdminRuleMatch      `json:"match"`
	Extra      []AdminRuleCondition `json:"extra_conditions"`
	Allowed    []domain.ID          `json:"allow_rule_ids"`
	Rate       *AdminRateOverride   `json:"rate_override"`
}

// AdminRuleCondition は同じ規制に追加するAND条件。条件ごとに別の効果を設定しない。
type AdminRuleCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

func (i AdminRuleInput) conditions() []denialCondition {
	m := i.match()
	out := []denialCondition{compactBodyCondition(denialCondition{m.Field, m.Operator, i.Target, "deny"})}
	for _, v := range i.Extra {
		out = append(out, compactBodyCondition(denialCondition{v.Field, v.Operator, v.Value, "deny"}))
	}
	return out
}

func (i AdminRuleInput) validate() error {
	m := i.match()
	if !validRuleEffect(denialEffect{Type: m.Effect, IDs: i.Allowed, Rate: i.Rate}) {
		return errors.New("invalid rule effect")
	}
	if len(i.Extra) > 7 {
		return errors.New("too many rule conditions")
	}
	seen := map[denialCondition]bool{}
	for _, c := range i.conditions() {
		if (c.Field == "line" || c.Field == "host") && m.Effect != "deny" {
			return errors.New("line conditions require deny")
		}
		if seen[c] {
			return errors.New("duplicate rule condition")
		}
		seen[c] = true
		if _, _, e := compileDenialCondition(c); e != nil {
			return e
		}
	}
	if !validDenyOperations(i.Operations) || i.Minutes < 1 || (i.Minutes > maxDenyMinutes && !((i.Minutes == permanentDenyMinutes || i.Minutes <= maxCapBanMinutes) && m.Field == "token" && m.Operator == "exact" && m.Effect == "deny" && len(i.Extra) == 0)) || !validDenyReason(i.Reason) {
		return errors.New("invalid deny rule")
	}
	return nil
}

// AdminRule は管理者が入力した対象だけを表示し、投稿者の私情報を新たに照会しない。
type AdminRule struct {
	ID         domain.ID            `json:"id"`
	Revision   domain.U64           `json:"revision"`
	Board      domain.ID            `json:"board_id"`
	Target     string               `json:"target"`
	Operations []string             `json:"operations"`
	Starts     string               `json:"starts_at"`
	Expires    string               `json:"expires_at"`
	Reason     string               `json:"reason_code"`
	Enabled    bool                 `json:"enabled"`
	RevokeCSRF string               `json:"revoke_csrf"`
	Match      AdminRuleMatch       `json:"match"`
	Extra      []AdminRuleCondition `json:"extra_conditions"`
	Allowed    []domain.ID          `json:"allow_rule_ids"`
	Rate       *AdminRateOverride   `json:"rate_override"`
}

func ruleDTO(v denialRule) AdminRule {
	out := AdminRule{Rate: cloneRateOverride(v.Effect.Rate), Allowed: slices.Clone(v.Effect.IDs), ID: v.ID, Revision: v.Revision, Board: v.Scope.Board, Target: v.Conditions[0].Value, Operations: append([]string{}, v.Operations...), Starts: time.Unix(0, int64(v.Starts)).UTC().Format(time.RFC3339Nano), Expires: time.Unix(0, int64(v.Expires)).UTC().Format(time.RFC3339Nano), Reason: v.Reason, Enabled: v.Enabled, Match: AdminRuleMatch{v.Conditions[0].Field, v.Conditions[0].Operator, v.Effect.Type}}
	for _, c := range v.Conditions[1:] {
		out.Extra = append(out.Extra, AdminRuleCondition{c.Field, c.Operator, c.Value})
	}
	return out
}
func (r AdminRule) ETag() string { return fmt.Sprintf(`"%s:%d"`, r.ID, r.Revision) }

// AdminRules は板内の全登録履歴。初期上限1000件、期限切れ・解除済みも保持する。
type AdminRules struct {
	Board    domain.ID   `json:"board_id"`
	Name     string      `json:"board_name"`
	Revision domain.U64  `json:"revision"`
	Rules    []AdminRule `json:"rules"`
}

func (r AdminRules) ETag() string { return fmt.Sprintf(`"%s:rules:%d"`, r.Board, r.Revision) }
func (b *postingBoard) adminRules() AdminRules {
	out := AdminRules{Board: b.owner, Name: b.boardName(), Rules: []AdminRule{}}
	for _, v := range b.sortedDenials() {
		out.Revision += v.Revision
		out.Rules = append(out.Rules, ruleDTO(v))
	}
	return out
}
func (r *Repository) adminRules(ctx context.Context, s adminauth.Session, id domain.ID) (AdminRules, error) {
	return r.adminRulesView(ctx, s, id, true)
}

// adminRulesView は役割と対象板の存在を必ず確認し、資産だけの検証では規制一覧を作らない。
func (r *Repository) adminRulesView(ctx context.Context, s adminauth.Session, id domain.ID, withRows bool) (AdminRules, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.authorizeAdmin(s, "board_admin", id); e != nil {
		return AdminRules{}, e
	}
	b := r.posting[id]
	if b == nil {
		return AdminRules{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	if !withRows {
		return AdminRules{Board: id, Name: b.boardName(), Rules: []AdminRule{}}, nil
	}
	v, e := b.worker.Submit(ctx, func() (any, error) { return b.adminRules(), nil })
	if e != nil {
		return AdminRules{}, e
	}
	return v.(AdminRules), nil
}

type ruleReceipt struct {
	ID      domain.ID   `json:"id"`
	Admin   domain.ID   `json:"admin_id"`
	Key     domain.Hash `json:"request_key_hmac"`
	Request domain.Hash `json:"request_hmac"`
	Result  denialRule  `json:"result"`
	Created domain.Time `json:"created_at_ns"`
	Expires domain.Time `json:"expires_at_ns"`
}

func validateRuleReceipt(key string, old, next []byte) error {
	var v ruleReceipt
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if key != v.Key.String() || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 {
		return store.ErrCorrupt
	}
	if v.Result.Effect.Type == "rate_override" || v.Result.Effect.Stopped != nil {
		if v.Result.Enabled && v.Result.Starts != v.Created || !v.Result.Enabled && (v.Result.Effect.Stopped == nil || *v.Result.Effect.Stopped != v.Created) {
			return store.ErrCorrupt
		}
	}
	if _, e := compileDenial(v.Result); e != nil {
		return e
	}
	if len(old) > 0 {
		var p ruleReceipt
		if e := strictjson.Decode(old, &p); e != nil {
			return e
		}
		if p.Expires > v.Created {
			return errors.New("rule receipt still active")
		}
	}
	return nil
}

// changeRule はruleIDがゼロなら登録、それ以外なら解除。操作内容と対象を要求HMACへ束縛する。
func (r *Repository) changeRule(ctx context.Context, s adminauth.Session, board, ruleID domain.ID, input AdminRuleInput, etag, key string) (AdminRule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.authorizeAdmin(s, "board_admin", board); e != nil {
		return AdminRule{}, e
	}
	if !adminRequestKey.MatchString(key) {
		return AdminRule{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminRule{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	creating := ruleID == (domain.ID{})
	if creating && input.Minutes == permanentDenyMinutes && !s.Reauthenticated(time.Now()) {
		return AdminRule{}, &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
	}
	if creating {
		if e := input.validate(); e != nil {
			return AdminRule{}, &adminFailure{status: 422, code: "INVALID_RULE"}
		}
	}
	if creating && input.match().Effect == "rate_override" && r.admission == nil {
		return AdminRule{}, &adminFailure{status: 422, code: "ADMISSION_NOT_ENABLED"}
	}
	if creating && input.match().Effect == "require_token" && r.anonymous == nil {
		return AdminRule{}, &adminFailure{status: 422, code: "ANONYMOUS_NOT_ENABLED"}
	}
	b := r.posting[board]
	if b == nil {
		return AdminRule{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	raw, e := json.Marshal(input)
	if e != nil {
		return AdminRule{}, e
	}
	requestKey := identity.MAC(b.dedupKey[:], "oimo/admin-rule-key/v1", s.Admin[:], board[:], []byte(key))
	request := identity.MAC(b.dedupKey[:], "oimo/admin-rule-change/v1", s.Admin[:], board[:], ruleID[:], raw, []byte(etag))
	v, e := b.worker.Submit(ctx, func() (any, error) {
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		now := domain.Time(time.Now().UnixNano())
		if prior, ok := b.control.State().Rows["rule_receipt:"+requestKey.String()]; ok {
			var p ruleReceipt
			if e := strictjson.Decode(prior.Value, &p); e != nil {
				return nil, e
			}
			if p.Created > now {
				return nil, ErrPostingUnavailable
			}
			if p.Expires > now {
				if p.Request != request {
					return nil, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
				}
				return ruleDTO(p.Result), nil
			}
		}
		rule, e := r.prepareRule(b, ruleID, input, etag, now)
		if e != nil {
			return nil, e
		}
		if input.Minutes != permanentDenyMinutes && input.Minutes > maxDenyMinutes {
			var site siteState
			if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
				return nil, e
			}
			if site.MinimumReader < capCommandsReader {
				site.MinimumReader = capCommandsReader
				if e := appendControl(r.site, "cap_commands_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{board.String()}); e != nil {
					r.stopped = true
					return nil, e
				}
			}
		}
		if rule.Expires == permanentDenyExpiry {
			if e = r.enableReportReviewReader(); e != nil {
				return nil, e
			}
		}
		if e = r.enableDenials(board, input.Match != nil, len(rule.Conditions) > 1 || rule.Conditions[0].Field == "ua", rule.Effect.Type == "allow_rule_ids", rule.Effect.Type == "rate_override" || rule.Effect.Stopped != nil, ruleHasLine(rule.Conditions), ruleRequiresReader32(rule.Conditions), ruleHasHost(rule.Conditions), mixedNetworkRule(rule.Conditions), specialNetworkRule(rule.Conditions)); e != nil {
			return nil, e
		}
		receipt := ruleReceipt{domain.NewID(), s.Admin, requestKey, request, rule, now, now + 86400e9}
		if e = b.saveRule(s, receipt); e != nil {
			r.stopped = true
			return nil, e
		}
		compiled, _ := compileDenial(rule)
		b.denials[rule.ID] = compiled
		if r.admission != nil {
			r.admission.installOverrides(b.owner, b.denials)
		}
		if creating {
			r.denialCount++
		}
		return ruleDTO(rule), nil
	})
	if e != nil {
		return AdminRule{}, e
	}
	return v.(AdminRule), nil
}
func (r *Repository) prepareRule(b *postingBoard, id domain.ID, input AdminRuleInput, etag string, now domain.Time) (denialRule, error) {
	if id != (domain.ID{}) {
		old, ok := b.denials[id]
		if !ok {
			return denialRule{}, &adminFailure{status: 404, code: "RULE_NOT_FOUND"}
		}
		if etag != ruleDTO(old.rule).ETag() {
			return denialRule{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
		}
		if !old.rule.Enabled {
			return denialRule{}, &adminFailure{status: 409, code: "RULE_ALREADY_REVOKED"}
		}
		rule := old.rule
		if rule.Effect.Type == "rate_override" || rule.Effect.Type == "allow_rule_ids" && allowTargetsOverride(b.denials, rule.Effect.IDs) {
			if e := b.checkRuleClock(now); e != nil {
				return denialRule{}, e
			}
			rule.Effect.Stopped = &now
		}
		rule.Enabled = false
		rule.Revision++
		return rule, nil
	}
	if etag != b.adminRules().ETag() {
		return denialRule{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	if len(b.denials) >= 1000 || r.denialCount >= 10000 {
		return denialRule{}, &adminFailure{status: 503, code: "RULE_CAPACITY"}
	}
	if now <= 0 || now > domain.Time(1<<63-1)-domain.Time(maxDenyMinutes)*domain.Time(time.Minute) {
		return denialRule{}, ErrPostingUnavailable
	}
	m := input.match()
	if m.Effect == "rate_override" {
		if e := b.checkRuleClock(now); e != nil {
			return denialRule{}, e
		}
		count := 0
		for _, entry := range b.denials {
			if entry.rule.Effect.Type == "rate_override" && entry.rule.Enabled && entry.rule.Expires > now {
				count++
			}
		}
		if count >= 12 {
			return denialRule{}, &adminFailure{status: 503, code: "RULE_CAPACITY"}
		}
	}
	if m.Effect == "allow_rule_ids" {
		if allowTargetsOverride(b.denials, input.Allowed) {
			if e := b.checkRuleClock(now); e != nil {
				return denialRule{}, e
			}
		}
		if e := validateAllowedTargets(b.denials, input.Allowed, now); e != nil {
			return denialRule{}, &adminFailure{status: 422, code: "INVALID_ALLOWED_RULES"}
		}
	}
	expires := permanentDenyExpiry
	if input.Minutes != permanentDenyMinutes {
		if now > permanentDenyExpiry-domain.Time(input.Minutes)*domain.Time(time.Minute) {
			return denialRule{}, ErrPostingUnavailable
		}
		expires = now + domain.Time(input.Minutes)*domain.Time(time.Minute)
	}
	return denialRule{domain.NewID(), 1, denialScope{"board", b.owner}, append([]string{}, input.Operations...), input.conditions(), denialEffect{Type: m.Effect, IDs: slices.Clone(input.Allowed), Rate: cloneRateOverride(input.Rate)}, 0, now, expires, input.Reason, true, nil, nil}, nil
}

// enableDenials は最低reader版を先に保存する。機能宣言だけで停止しても旧規制状態を維持する。
func (r *Repository) enableDenials(board domain.ID, extended, composite, allow, rate bool, line ...bool) error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	requiredReader := uint32(8)
	if len(line) > 0 && line[0] {
		requiredReader = 29
	}
	if len(line) > 1 && line[1] {
		requiredReader = 32
	}
	if len(line) > 2 && line[2] {
		requiredReader = 64
	}
	if len(line) > 3 && line[3] {
		requiredReader = max(requiredReader, mixedNetworkReader)
	}
	if len(line) > 4 && line[4] {
		requiredReader = max(requiredReader, specialNetworkReader)
	}
	if extended {
		requiredReader = max(requiredReader, 18)
	}
	if composite {
		requiredReader = max(requiredReader, 20)
	}
	if allow {
		requiredReader = max(requiredReader, 23)
	}
	if rate {
		requiredReader = max(requiredReader, 24)
	}
	if site.MinimumReader >= requiredReader {
		return nil
	}
	site.MinimumReader = requiredReader
	if e := appendControl(r.site, "denial_rules_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{board.String()}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}

// saveRule は板ルール・再送結果・操作者を同じframeでSyncする。失敗時は結果不明として停止する。
func (b *postingBoard) saveRule(s adminauth.Session, receipt ruleReceipt) error {
	state := b.control.State()
	count := 0
	for k := range state.Rows {
		if strings.HasPrefix(k, "rule_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) {
		return ErrPostingUnavailable
	}
	rule := receipt.Result
	changes := []store.Mutation{mutation("board_rule", rule.ID.String(), rule, nil), mutation("rule_receipt", receipt.Key.String(), receipt, nil)}
	for i := range changes {
		changes[i].ExpectedRevision = state.Rows[changes[i].Collection+":"+changes[i].Key].Revision
	}
	reason := "rule_create"
	if !rule.Enabled {
		reason = "rule_revoke"
	}
	keyID := uint32(8)
	op := store.ControlOperation{Schema: 1, Seq: state.Seq + 1, ExpectedSeq: state.Seq, Committed: receipt.Created, Actor: domain.Actor{Kind: "admin", ID: &s.Admin, Reason: reason, Request: &receipt.Request, Idempotency: &receipt.Key, KeyID: &keyID}, Mutations: changes, Result: store.ControlResult{Code: reason, Targets: []string{rule.ID.String()}, RequestKey: &receipt.Key, Request: &receipt.Request, KeyID: &keyID, Expires: &receipt.Expires}}
	raw, e := json.Marshal(op)
	if e != nil {
		return e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Seq), Records: []store.Record{{ID: receipt.ID, JSON: raw}}})
	if e != nil {
		return e
	}
	if b.control.Append(frame).Status != store.Durable {
		b.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: receipt.ID}
	}
	return nil
}

// ruleHasHost は保存前にホスト条件用reader版を宣言する。
func ruleHasHost(conditions []denialCondition) bool {
	for _, c := range conditions {
		if c.Field == "host" {
			return true
		}
	}
	return false
}

// Permanent は保存済み無期限規制を管理表示用に識別する。
func (r AdminRule) Permanent() bool {
	return r.Expires == time.Unix(0, int64(permanentDenyExpiry)).UTC().Format(time.RFC3339Nano)
}
