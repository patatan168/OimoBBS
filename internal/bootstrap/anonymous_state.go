// 匿名Cookieの有効化・発行履歴・失効を厳密なsite control型として保持する。
package bootstrap

import (
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"reflect"
)

// AnonymousPolicy は匿名Cookie機能の永続設定。鍵そのものは含まない。
type AnonymousPolicy struct {
	Schema     string                  `json:"schema"`
	Mode       string                  `json:"mode"`
	Enabled    domain.Time             `json:"enabled_at_ns"`
	Generation domain.U64              `json:"generation"`
	KeyID      uint32                  `json:"key_id"`
	ReplyRule  domain.ID               `json:"reply_rule_id"`
	CreateRule domain.ID               `json:"create_rule_id"`
	Modes      []anonymousModeBoundary `json:"mode_history"`
}

type anonymousModeBoundary struct {
	At   domain.Time `json:"changed_at_ns"`
	Mode string      `json:"mode"`
}

// modeAt は機能開始前だけoff、それ以後は必須条件を返す。
func (p AnonymousPolicy) modeAt(at domain.Time) string {
	if at < p.Enabled {
		return "off"
	}
	return p.Mode
}

// anonymousReceiptModeMatches は保存時点の必須条件と一致する結果だけを認める。
func anonymousReceiptModeMatches(p AnonymousPolicy, receipt anonymousReceipt) bool {
	return receipt.Result.Mode == p.modeAt(receipt.Created)
}

type tokenIssue struct {
	ID      domain.ID   `json:"id"`
	Subject domain.Hash `json:"subject_hmac"`
	Network domain.Hash `json:"network_hmac"`
	KeyID   uint32      `json:"key_id"`
	Issued  domain.Time `json:"issued_at_ns"`
	Expires domain.Time `json:"expires_at_ns"`
}

type tokenRevocation struct {
	ID         domain.ID   `json:"id"`
	Subject    domain.Hash `json:"token_id_hash"`
	KeyID      uint32      `json:"key_id"`
	Generation domain.U64  `json:"generation"`
	Revoked    domain.Time `json:"revoked_at_ns"`
	Expires    domain.Time `json:"expires_at_ns"`
	Reason     string      `json:"reason_code"`
}

func decodeAnonymous(raw []byte) (AnonymousPolicy, error) {
	var p AnonymousPolicy
	e := strictjson.Decode(raw, &p)
	if e != nil {
		return p, e
	}
	if p.Schema != "anon-policy-v4" || p.Mode != "required" || p.Modes == nil || len(p.Modes) != 0 || p.Enabled <= 0 || p.Generation == 0 || p.KeyID != 4 || p.ReplyRule == (domain.ID{}) || p.CreateRule == (domain.ID{}) || p.ReplyRule == p.CreateRule {
		return p, errors.New("invalid anonymous policy")
	}

	return p, nil
}
func validateAnonymousValue(collection, key string, old, next []byte) error {
	switch collection {
	case "anon_policy":
		if key != "active" {
			return errors.New("invalid anonymous policy key")
		}
		p, e := decodeAnonymous(next)
		if e != nil {
			return e
		}
		if len(old) > 0 {
			prior, e := decodeAnonymous(old)
			if e != nil {
				return e
			}
			return validateAnonymousTransition(prior, p)
		}
	case "token_reissue":
		return validateTokenReissue(key, old, next)
	case "token_issue":
		var v tokenIssue
		if e := strictjson.Decode(next, &v); e != nil {
			return e
		}
		if len(old) > 0 || key != v.ID.String() || v.ID == (domain.ID{}) || v.Subject == (domain.Hash{}) || v.Network == (domain.Hash{}) || v.KeyID != 7 || v.Issued <= 0 || v.Issued > domain.Time(1<<63-1)-3660e9 || v.Expires != v.Issued+3660e9 {
			return errors.New("invalid token issue")
		}
	case "token_revocation":
		var v tokenRevocation
		if e := strictjson.Decode(next, &v); e != nil {
			return e
		}
		if len(old) > 0 || key != v.Subject.String() || v.ID == (domain.ID{}) || v.Subject == (domain.Hash{}) || v.KeyID != 4 || v.Generation == 0 || v.Revoked <= 0 || v.Revoked > domain.Time(1<<63-1)-31*86400e9 || v.Expires != v.Revoked+31*86400e9 || v.Reason != "local_admin" {
			return errors.New("invalid token revocation")
		}
	default:
		return errors.New("invalid anonymous collection")
	}
	return nil
}

// validateAnonymousTransition は同じ主体設定の全体失効だけを許可する。
func validateAnonymousTransition(prior, next AnonymousPolicy) error {
	if prior.Schema != "anon-policy-v4" || next.Schema != "anon-policy-v4" || prior.Generation == ^domain.U64(0) || next.Generation != prior.Generation+1 {
		return errors.New("invalid anonymous transition")
	}
	candidate := prior
	candidate.Generation = next.Generation
	if !reflect.DeepEqual(candidate, next) {
		return errors.New("anonymous policy identity changed")
	}
	return nil
}
