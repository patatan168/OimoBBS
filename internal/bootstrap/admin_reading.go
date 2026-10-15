// 閲覧設定の保存を管理権限・再送照会・CAS・監査付きSyncで確定する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// AdminReading は対象ごとの設定と保存版。管理用の秘密は含めない。
type AdminReading struct {
	Scope    string        `json:"scope"`
	Policy   ReadingPolicy `json:"policy"`
	Revision domain.U64    `json:"revision"`
}

// ETag は対象スコープと保存版に束縛した版比較の値を返す。
func (v AdminReading) ETag() string { return fmt.Sprintf(`"reading:%s:%d"`, v.Scope, v.Revision) }

// authorizeReadingLocked は板担当の管理者へ担当板だけの編集を許可する。
func (r *Repository) authorizeReadingLocked(s adminauth.Session, scope string, write bool) error {
	owner, err := readingScope(scope)
	if err != nil {
		return &adminFailure{status: 400, code: "INVALID_SCOPE"}
	}
	role := "site_admin"
	if owner != (domain.ID{}) {
		role = "board_admin"
	}
	if err := r.authorizeAdmin(s, role, owner); err != nil {
		return err
	}
	if owner != (domain.ID{}) && r.posting[owner] == nil {
		return &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	return nil
}
func (r *Repository) readingViewLocked(scope string) AdminReading {
	p := defaultReadingPolicy()
	if v := r.liveReading.Load(); v != nil && v.Policies[scope] != nil {
		p = v.Policies[scope].Policy
	}
	return AdminReading{scope, p, r.site.State().Rows["reading_access:"+scope].Revision}
}
func (r *Repository) adminReading(s adminauth.Session, scope string) (AdminReading, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.authorizeReadingLocked(s, scope, false); err != nil {
		return AdminReading{}, err
	}
	return r.readingViewLocked(scope), nil
}

// updateReading は保存完了後に不変設定を交換する。管理用設定は現在の接続元を拒否する保存を防ぐ。
func (r *Repository) updateReading(s adminauth.Session, scope string, p ReadingPolicy, etag, key string, ip netip.Addr, agent string) (AdminReading, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.authorizeReadingLocked(s, scope, true); err != nil {
		return AdminReading{}, err
	}
	if err := r.available(); err != nil {
		return AdminReading{}, err
	}
	compiled, err := compileReadingPolicy(p)
	if err != nil {
		return AdminReading{}, &adminFailure{status: 422, code: "INVALID_READING_POLICY"}
	}
	if !adminRequestKey.MatchString(key) {
		return AdminReading{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminReading{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return AdminReading{}, err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return AdminReading{}, err
	}
	defer clear(secret[:])
	requestKey := identity.MAC(secret[:], "oimo/admin-key/v1", s.Admin[:], []byte(key))
	raw, _ := json.Marshal(p)
	request := identity.MAC(secret[:], "oimo/reading-access/v1", s.Admin[:], []byte(scope), raw, []byte(etag))
	now := domain.Time(time.Now().UnixNano())
	state := r.site.State()
	if prior, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var receipt struct {
			Request  domain.Hash `json:"request_hmac"`
			Created  domain.Time `json:"created_at_ns"`
			Expires  domain.Time `json:"expires_at_ns"`
			Revision domain.U64  `json:"revision"`
		}
		if err := json.Unmarshal(prior.Value, &receipt); err != nil {
			return AdminReading{}, err
		}
		if receipt.Created > now {
			return AdminReading{}, ErrPostingUnavailable
		}
		if receipt.Expires > now {
			if receipt.Request != request {
				return AdminReading{}, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			return AdminReading{scope, p, receipt.Revision}, nil
		}
	}
	view := r.readingViewLocked(scope)
	if view.ETag() != etag {
		return AdminReading{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	if scope == "admin" && compiled.check(r.liveNetworks.Load(), ip, agent) != nil {
		return AdminReading{}, &adminFailure{status: 422, code: "ADMIN_SELF_LOCKOUT"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) {
		return AdminReading{}, ErrPostingUnavailable
	}
	var site siteState
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return AdminReading{}, err
	}
	site.MinimumReader = max(site.MinimumReader, 83)
	if mixedNetworkAccess(&p.Network) {
		site.MinimumReader = max(site.MinimumReader, mixedNetworkReader)
	}
	site.PublicRevision = state.Seq + 1
	id := domain.NewID()
	receipt := adminReceipt{ID: id, Admin: s.Admin, Key: requestKey, Request: request, Name: "閲覧制限", Revision: state.Seq + 1, Created: now, Expires: now + 86400e9}
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("reading_access", scope, p, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
	kid := uint32(8)
	target := scope
	if scope == "site" || scope == "admin" {
		target = site.ID.String()
	}
	frame, err := controlFrame(state, id, now, "reading_access_update", changes, []string{target}, domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "reading_access_update", Request: &request, Idempotency: &requestKey, KeyID: &kid})
	if err != nil {
		return AdminReading{}, err
	}
	if r.site.Append(frame).Status != store.Durable {
		r.stopped = true
		return AdminReading{}, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	next, err := loadReadingSnapshot(r.site.State())
	if err != nil {
		r.stopped = true
		return AdminReading{}, err
	}
	r.liveReading.Store(next)
	r.publicRevision.Store(uint64(site.PublicRevision))
	return r.readingViewLocked(scope), nil
}

// ResetAdminReadingAccess は停止中CLIで管理画面の接続制限だけをOFFにする。パスワードは維持する。
// データディレクトリの排他を取得したRepositoryだけで実行する。
func (r *Repository) ResetAdminReadingAccess() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return err
	}
	if _, exists := r.site.State().Rows["reading_access:admin"]; !exists {
		return nil
	}
	p := r.readingViewLocked("admin").Policy
	p.Enabled = false
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	site.MinimumReader = max(site.MinimumReader, 83)
	if mixedNetworkAccess(&p.Network) {
		site.MinimumReader = max(site.MinimumReader, mixedNetworkReader)
	}
	if err := appendControl(r.site, "admin_reading_reset", []store.Mutation{mutation("site", "state", site, nil), mutation("reading_access", "admin", p, nil)}, []string{}); err != nil {
		r.stopped = true
		return err
	}
	next, err := loadReadingSnapshot(r.site.State())
	if err != nil {
		r.stopped = true
		return err
	}
	r.liveReading.Store(next)
	return nil
}
