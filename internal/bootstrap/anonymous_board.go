// 板別の匿名Cookie設定を復号し、全投稿必須の条件と利用開始待ちを判定する。
package bootstrap

import (
	"errors"
	"fmt"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strings"
	"time"
)

// AdminAnonymousSettings は板のモードと現在の署名Cookie発行からの待ち秒数。
// 公開投稿の実効モードは常にrequired。
type AdminAnonymousSettings struct {
	Mode string `json:"cookie_mode"`
	Wait uint32 `json:"token_wait_seconds"`
}

// validate は待ち時間によるCookieなし投稿の迂回を防ぐため、非ゼロ待ちを必須板に限定する。
func (a AdminAnonymousSettings) validate() error {
	if a.Mode != "required" || a.Wait > 3600 {
		return errors.New("invalid anonymous board settings")
	}
	return nil
}
func (v AdminBoardEdit) anonymous() AdminAnonymousSettings {
	if v.Anonymous == nil {
		return AdminAnonymousSettings{Mode: "required"}
	}
	return *v.Anonymous
}

// effectiveAnonymous は全投稿の必須条件と板の待ち時間を返す。
func effectiveAnonymous(a *anonymousState, p boardPosting) (string, uint32) {
	if a == nil {
		return "off", 0
	}
	return "required", p.TokenWait
}

// ErrAnonymousRecast は正常更新を除いたCookie再発行後の投稿待機を表す。
var ErrAnonymousRecast = errors.New("anonymous cookie reissue cooldown")

// anonymousWait は板の利用開始待ちと署名済み再発行待ちを予約前に検査し、秒単位で切り上げる。
func anonymousWait(token abuse.Anon, seconds uint32, now time.Time) error {
	if seconds == 0 && token.ReadyAt == 0 {
		return nil
	}
	if token.ID == ([16]byte{}) {
		return abuse.ErrToken
	}
	ready := time.Unix(max(token.Issued+int64(seconds), token.ReadyAt), 0)
	if now.Before(ready) {
		limited := &abuse.RateLimited{RetryAfter: uint64((ready.Sub(now) + time.Second - 1) / time.Second)}
		if token.ReadyAt > now.Unix() {
			return fmt.Errorf("%w: %w", ErrAnonymousRecast, limited)
		}
		return limited
	}
	return nil
}

// validateAnonymousBoardFeatures は通常起動と隔離再生で最低reader版・機能の存在を同じように照合する。
func validateAnonymousBoardFeatures(site, board store.ControlState) error {
	var s siteState
	var b boardValue
	if e := strictjson.Decode(site.Rows["site:state"].Value, &s); e != nil {
		return e
	}
	if e := strictjson.Decode(board.Rows["board:state"].Value, &b); e != nil {
		return e
	}
	if e := validateIdentityReader(s, b); e != nil {
		return e
	}
	if (b.Settings.Posting.Create == "cap_only" || b.Settings.Posting.Reply == "cap_only") && s.MinimumReader < 22 {
		return errors.New("cap_only requires reader 22")
	}
	for name := range board.Rows {
		if (strings.HasPrefix(name, "local_rules:") || strings.HasPrefix(name, "local_rules_receipt:")) && s.MinimumReader < 72 {
			return errors.New("local rules require reader 72")
		}
	}
	enabled := site.Rows["anon_policy:active"].Revision != 0
	policies, e := postingPolicies(board)
	if e != nil {
		return e
	}
	for _, p := range policies {
		if s.MinimumReader < 19 || !enabled || p.At > domain.Time(time.Now().UnixNano()) {
			return errors.New("online posting policy boundary mismatch")
		}
	}

	if b.Settings.Posting.Cookie != "required" || b.Settings.Posting.TokenWait > 0 && (s.MinimumReader < 18 || !enabled) {
		return errors.New("invalid mandatory Cookie board settings")
	}
	for key, row := range board.Rows {
		if !strings.HasPrefix(key, "board_rule:") {
			continue
		}
		var rule denialRule
		if e := strictjson.Decode(row.Value, &rule); e != nil {
			return e
		}
		if _, e := compileDenial(rule); e != nil {
			return e
		}
		if rule.ReportPolicy != nil && s.MinimumReader < 69 {
			return store.ErrCorrupt
		}
		if (len(rule.Reports) > 0 || rule.Expires == permanentDenyExpiry) && s.MinimumReader < 67 {
			return store.ErrCorrupt
		}
		for _, c := range rule.Conditions {
			if c.Field == "line" && specialNetworkKind(c.Value) && s.MinimumReader < specialNetworkReader {
				return store.ErrCorrupt
			}
			if c.Field == "line" && c.Value == "mixed" && s.MinimumReader < mixedNetworkReader {
				return store.ErrCorrupt
			}
			if c.Field == "host" && s.MinimumReader < 64 {
				return errors.New("host rule requires reader 64")
			}
			if c.Field == "line" && (c.Value == "vpn" || c.Value == "foreign") && s.MinimumReader < 32 {
				return store.ErrCorrupt
			}
			if c.Field == "line" && s.MinimumReader < 29 {
				return errors.New("line rule requires reader 29")
			}
		}
		if len(rule.Conditions) > 1 && s.MinimumReader < 20 {
			return errors.New("composite rules require reader 20")
		}
		for _, condition := range rule.Conditions {
			if condition.Field == "ua" && s.MinimumReader < 20 {
				return errors.New("UA rules require reader 20")
			}
		}
		if rule.Effect.Type == "rate_override" {
			policy, err := validateAdmission(site.Rows["rate_policy:active"].Value)
			if err != nil || rule.Starts < policy.Enabled {
				return errors.New("rate override activation boundary mismatch")
			}
		}
		if (rule.Effect.Type == "rate_override" || rule.Effect.Stopped != nil) && (s.MinimumReader < 24 || site.Rows["rate_policy:active"].Revision == 0) {
			return errors.New("rate override requires reader 24 and admission")
		}
		if rule.Effect.Type == "allow_rule_ids" && s.MinimumReader < 23 {
			return errors.New("allow rules require reader 23")
		}
		if (rule.Effect.Type != "deny" || rule.Conditions[0].Field != "ip" && rule.Conditions[0].Field != "network") && s.MinimumReader < 18 {
			return errors.New("extended rules require reader 18")
		}
		if rule.Effect.Type == "require_token" && !enabled {
			return errors.New("token rule without anonymous policy")
		}
	}
	return nil
}
