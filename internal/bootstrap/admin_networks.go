// 共通回線設定へ管理者認可・CAS・固定再送と耐久保存を適用する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strings"
	"time"
)

type networkReceipt struct {
	Type    string      `json:"type"`
	ID      domain.ID   `json:"id"`
	Admin   domain.ID   `json:"admin_id"`
	Key     domain.Hash `json:"request_key_hmac"`
	Request domain.Hash `json:"request_hmac"`
	Version domain.U64  `json:"version"`
	Created domain.Time `json:"created_at_ns"`
	Expires domain.Time `json:"expires_at_ns"`
}

func isNetworkReceipt(raw []byte) bool {
	var v struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(raw, &v) == nil && v.Type == "network_change"
}
func validateNetworkReceipt(key string, old, next []byte) error {
	var v networkReceipt
	if strictjson.Decode(next, &v) != nil || v.Type != "network_change" || key != v.Key.String() || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Version == 0 || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 {
		return store.ErrCorrupt
	}
	if len(old) > 0 {
		var p networkReceipt
		if strictjson.Decode(old, &p) != nil || v.Created < p.Expires {
			return store.ErrCorrupt
		}
	}
	return nil
}

// changeNetworks は設定とreceiptを同時保存する。同一要求は再取得を開始せず結果だけを確認する。
func (r *Repository) changeNetworks(s adminauth.Session, config NetworkConfig, etag, key string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return false, e
	}
	if e := r.authorizeAdmin(s, "site_admin", domain.ID{}); e != nil {
		return false, e
	}
	if config.validate() != nil {
		return false, &adminFailure{status: 422, code: "INVALID_NETWORK_SETTINGS"}
	}
	if !adminRequestKey.MatchString(key) {
		return false, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	secret, e := readPrivateKeyForAnonymous(r)
	if e != nil {
		return false, e
	}
	defer clear(secret[:])
	requestKey := identity.MAC(secret[:], "oimo/admin-network-key/v1", s.Admin[:], []byte(key))
	raw, _ := json.Marshal(config)
	request := identity.MAC(secret[:], "oimo/admin-network-change/v1", s.Admin[:], []byte(etag), raw)
	now := domain.Time(time.Now().UnixNano())
	state := r.site.State()
	if row, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		if !isNetworkReceipt(row.Value) {
			return false, &adminFailure{status: 409, code: "REQUEST_KEY_CONFLICT"}
		}
		var prior networkReceipt
		if strictjson.Decode(row.Value, &prior) != nil {
			return false, store.ErrCorrupt
		}
		if now < prior.Expires {
			if prior.Request != request {
				return false, &adminFailure{status: 409, code: "REQUEST_KEY_CONFLICT"}
			}
			return true, nil
		}
	}
	if etag != networkETag(uint64(state.Rows["network:active"].Revision)) {
		return false, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || now > domain.Time(1<<63-1)-86400e9 {
		return false, ErrPostingUnavailable
	}
	next, e := loadNetworkState(state)
	if e != nil {
		return false, e
	}
	if next.Version == ^domain.U64(0) {
		return false, store.ErrCorrupt
	}
	if config.DNSMode == "" {
		config.DNSMode = next.Config.DNSMode
	}
	next.Version++
	next.Config = config
	receipt := networkReceipt{Type: "network_change", ID: domain.NewID(), Admin: s.Admin, Key: requestKey, Request: request, Version: next.Version, Created: now, Expires: now + 86400e9}
	keyID := uint32(8)
	actor := domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "network_config", Request: &request, Idempotency: &requestKey, KeyID: &keyID}
	if e = r.publishNetworks(next, []store.Mutation{mutation("admin_receipt", requestKey.String(), receipt, nil)}, "network_config", &actor); e != nil {
		return false, e
	}
	r.wakeNetworkUpdater(false)
	return false, nil
}
