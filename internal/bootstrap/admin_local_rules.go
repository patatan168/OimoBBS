// 板のローカルルールを認可・競合検出・永続再送の下で設定する。
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
	"strings"
	"time"
)

// LocalRules は段落・箇条書き・リンクからなるローカルルール設定。
type LocalRules struct {
	Rules []ruleParagraph `json:"rules"`
}

// AdminLocalRules は板IDと競合検出用の版を含む管理設定。
type AdminLocalRules struct {
	Board    domain.ID  `json:"board_id"`
	Revision domain.U64 `json:"revision"`
	Settings LocalRules `json:"settings"`
}

// ETag はローカルルールの更新時に比較する版を返す。
func (v AdminLocalRules) ETag() string {
	return fmt.Sprintf(`"%s:local-rules:%d"`, v.Board, v.Revision)
}

// validate は保存前と復旧時にローカルルールの構造と入力上限を検査する。
func (v LocalRules) validate() error { return validateLocalRules(v.Rules) }

// localRules は板ワーカー内で設定を取得し、未設定なら空のルールを返す。
func (b *postingBoard) localRules() (AdminLocalRules, error) {
	result := AdminLocalRules{Board: b.owner, Settings: LocalRules{Rules: []ruleParagraph{}}}
	if row, ok := b.control.State().Rows["local_rules:active"]; ok {
		if e := strictjson.Decode(row.Value, &result.Settings); e != nil {
			return result, e
		}
		result.Revision = row.Revision
	}
	return result, nil
}

type localRulesReceipt struct {
	ID      domain.ID       `json:"id"`
	Admin   domain.ID       `json:"admin_id"`
	Key     domain.Hash     `json:"request_key_hmac"`
	Request domain.Hash     `json:"request_hmac"`
	Result  AdminLocalRules `json:"result"`
	Created domain.Time     `json:"created_at_ns"`
	Expires domain.Time     `json:"expires_at_ns"`
}

// validateLocalRulesValue はcontrol行と再送記録の形式・保持期限を検査する。
func validateLocalRulesValue(collection, key string, old, next json.RawMessage) error {
	if collection == "local_rules" {
		if key != "active" {
			return store.ErrCorrupt
		}
		var v LocalRules
		if e := strictjson.Decode(next, &v); e != nil {
			return e
		}
		return v.validate()
	}
	var v localRulesReceipt
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if collection != "local_rules_receipt" || key != v.Key.String() || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Result.Board == (domain.ID{}) || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.Result.Revision == 0 || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 {
		return store.ErrCorrupt
	}
	if e := v.Result.Settings.validate(); e != nil {
		return e
	}
	if len(old) > 0 {
		var before localRulesReceipt
		if e := strictjson.Decode(old, &before); e != nil {
			return e
		}
		if before.Expires > v.Created {
			return store.ErrCorrupt
		}
	}
	return nil
}

// adminLocalRules は認可と板ワーカーの排他の下で設定を取得・保存する。edit=nilなら取得だけ。
func (r *Repository) adminLocalRules(ctx context.Context, s adminauth.Session, id domain.ID, edit *LocalRules, etag, key string) (AdminLocalRules, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	role := "board_admin"
	if e := r.authorizeAdmin(s, role, id); e != nil {
		return AdminLocalRules{}, e
	}
	b := r.posting[id]
	if b == nil {
		return AdminLocalRules{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	if edit != nil {
		if !adminRequestKey.MatchString(key) {
			return AdminLocalRules{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
		}
		if etag == "" {
			return AdminLocalRules{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
		}
		if e := edit.validate(); e != nil {
			return AdminLocalRules{}, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		current, e := b.localRules()
		if e != nil || edit == nil {
			return current, e
		}
		state := b.control.State()
		now := domain.Time(time.Now().UnixNano())
		raw, _ := json.Marshal(edit)
		requestKey := identity.MAC(b.dedupKey[:], "oimo/local-rules-key/v1", s.Admin[:], id[:], []byte(key))
		request := identity.MAC(b.dedupKey[:], "oimo/local-rules/v1", s.Admin[:], id[:], raw, []byte(etag))
		if prior, ok := state.Rows["local_rules_receipt:"+requestKey.String()]; ok {
			var p localRulesReceipt
			if e = strictjson.Decode(prior.Value, &p); e != nil {
				return nil, e
			}
			if p.Created > now {
				return nil, ErrPostingUnavailable
			}
			if p.Expires > now {
				if p.Request != request {
					return nil, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
				}
				return p.Result, nil
			}
		}
		if current.ETag() != etag {
			return nil, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
		}
		count := 0
		for name := range state.Rows {
			if strings.HasPrefix(name, "local_rules_receipt:") {
				count++
			}
		}
		if count >= 200000 || state.Seq == ^domain.U64(0) {
			return nil, ErrPostingUnavailable
		}
		var site siteState
		if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
			return nil, e
		}
		if site.MinimumReader < 72 {
			site.MinimumReader = 72
			if e = appendControl(r.site, "local_rules_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{id.String()}); e != nil {
				r.stopped = true
				return nil, e
			}
		}
		result := AdminLocalRules{id, state.Seq + 1, *edit}
		receipt := localRulesReceipt{domain.NewID(), s.Admin, requestKey, request, result, now, now + 86400e9}
		mutations := []store.Mutation{mutation("local_rules", "active", edit, nil), mutation("local_rules_receipt", requestKey.String(), receipt, nil)}
		for i := range mutations {
			mutations[i].ExpectedRevision = state.Rows[mutations[i].Collection+":"+mutations[i].Key].Revision
		}
		keyID := uint32(8)
		op := store.ControlOperation{Schema: 1, Seq: state.Seq + 1, ExpectedSeq: state.Seq, Committed: now, Actor: domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "local_rules_update", Request: &request, Idempotency: &requestKey, KeyID: &keyID}, Mutations: mutations, Result: store.ControlResult{Code: "local_rules_updated", Targets: []string{id.String()}, RequestKey: &requestKey, Request: &request, KeyID: &keyID, Expires: &receipt.Expires}}
		encoded, e := json.Marshal(op)
		if e != nil {
			return nil, e
		}
		frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Seq), Records: []store.Record{{ID: receipt.ID, JSON: encoded}}})
		if e != nil {
			return nil, e
		}
		if commit := b.control.Append(frame); commit.Status != store.Durable {
			b.stopped = true
			return nil, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: receipt.ID}
		}
		return result, nil
	})
	if e != nil {
		return AdminLocalRules{}, e
	}
	result, ok := value.(AdminLocalRules)
	if !ok {
		return AdminLocalRules{}, errors.New("invalid local rules result")
	}
	return result, nil
}
