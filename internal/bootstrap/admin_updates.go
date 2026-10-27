// ソフトウェア更新はサイト管理者の再認証と確認済みSHAに限定し、停止前に要求を監査へ保存する。
package bootstrap

import (
	"path/filepath"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// recordSoftwareUpdateLocked は再送を同じ監査記録へ束縛する。呼出元はsite mutexを保持する。
func (r *Repository) recordSoftwareUpdateLocked(s adminauth.Session, token, revision string) error {
	if err := r.authorizeAccountChange(s); err != nil {
		return err
	}
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return err
	}
	defer clear(secret[:])
	key := identity.MAC(secret[:], "oimo/software-update-key/v1", s.Admin[:], []byte(token))
	request := identity.MAC(secret[:], "oimo/software-update-request/v1", s.Admin[:], []byte(token), []byte(revision))
	state := r.site.State()
	now := domain.Time(time.Now().UnixNano())
	if row, ok := state.Rows["admin_receipt:"+key.String()]; ok {
		var prior adminReceipt
		if err := strictjson.Decode(row.Value, &prior); err != nil {
			return err
		}
		if prior.Request == request && prior.Expires > now {
			return nil
		}
		return &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
	}
	if controlCollectionCount(state, "admin_receipt") >= 200000 {
		return ErrPostingUnavailable
	}
	id := domain.NewID()
	receipt := adminReceipt{ID: id, Admin: s.Admin, Key: key, Request: request, Name: "software_update:" + revision, Revision: state.Seq + 1, Created: now, Expires: now + 86400e9}
	kid := uint32(8)
	actor := domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "software_update_request", Request: &request, Idempotency: &key, KeyID: &kid}
	frame, err := controlFrame(state, id, now, "software_update_request", []store.Mutation{mutation("admin_receipt", key.String(), receipt, nil)}, []string{siteID(state).String()}, actor)
	if err != nil {
		return err
	}
	if r.site.Append(frame).Status != store.Durable {
		r.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	return nil
}

// controlCollectionCount は上限判定にだけ使い、保存値の内容は読み取らない。
func controlCollectionCount(state store.ControlState, collection string) int {
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, collection+":") {
			count++
		}
	}
	return count
}
