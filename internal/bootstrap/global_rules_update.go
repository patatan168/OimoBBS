// 全板規制の追加・解除を再認証・CAS・冪等性・監査と同じ耐久frameで保存する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"time"
)

func (r *Repository) updateGlobalRules(s adminauth.Session, value GlobalRuleSettings, etag, key string, payload []byte) (AdminGlobalRules, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rawNext, _ := json.Marshal(value)
	var rawOld json.RawMessage
	if row, ok := r.site.State().Rows["global_rules:active"]; ok {
		rawOld = row.Value
	}
	if value.validate() != nil {
		return AdminGlobalRules{}, &adminFailure{status: 422, code: "INVALID_GLOBAL_RULES"}
	}
	if err := r.currentAdministrator(s); err != nil {
		return AdminGlobalRules{}, err
	}
	if err := r.available(); err != nil {
		return AdminGlobalRules{}, err
	}
	if !s.Reauthenticated(time.Now()) {
		return AdminGlobalRules{}, &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
	}
	if !adminRequestKey.MatchString(key) {
		return AdminGlobalRules{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminGlobalRules{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return AdminGlobalRules{}, err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return AdminGlobalRules{}, err
	}
	defer clear(secret[:])
	requestKey := identity.MAC(secret[:], "oimo/admin-key/v1", s.Admin[:], []byte(key))
	request := identity.MAC(secret[:], "oimo/global-rules-update/v1", s.Admin[:], payload, []byte(etag))
	now := domain.Time(time.Now().UnixNano())
	state := r.site.State()
	if prior, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var receipt adminReceipt
		if err = strictjson.Decode(prior.Value, &receipt); err != nil {
			return AdminGlobalRules{}, err
		}
		if receipt.Created > now {
			return AdminGlobalRules{}, ErrControlExpiryClock
		}
		if receipt.Expires > now {
			if receipt.Request != request {
				return AdminGlobalRules{}, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			return r.globalRulesViewLocked(), nil
		}
	}
	if r.globalRulesViewLocked().ETag() != etag {
		return AdminGlobalRules{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	if string(rawOld) == string(rawNext) {
		return AdminGlobalRules{}, &adminFailure{status: 409, code: "RULE_ALREADY_REVOKED"}
	}
	if validateGlobalRules("active", rawOld, rawNext) != nil {
		return AdminGlobalRules{}, &adminFailure{status: 422, code: "INVALID_GLOBAL_RULES"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) {
		return AdminGlobalRules{}, ErrPostingUnavailable
	}
	var site siteState
	if err = strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return AdminGlobalRules{}, err
	}
	site.MinimumReader = max(site.MinimumReader, globalRulesReader)
	id := domain.NewID()
	receipt := adminReceipt{ID: id, Admin: s.Admin, Key: requestKey, Request: request, Name: "掲示板全体の投稿規制", Revision: state.Seq + 1, Created: now, Expires: now + 86400e9}
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("global_rules", "active", value, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
	kid := uint32(8)
	frame, err := controlFrame(state, id, now, "global_rules_update", changes, []string{site.ID.String()}, domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "global_rules_update", Request: &request, Idempotency: &requestKey, KeyID: &kid})
	if err != nil {
		return AdminGlobalRules{}, err
	}
	if r.site.Append(frame).Status != store.Durable {
		r.stopped = true
		return AdminGlobalRules{}, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	r.publishGlobalRules(value)
	return r.globalRulesViewLocked(), nil
}
