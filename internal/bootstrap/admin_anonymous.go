// 稼働中のCookie失効をサイト所有列でSyncし、不変の認証状態を全板へ配布する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"time"
)

// AdminAnonymous はCookieの署名・ID原文・主体一覧を持たない管理用状態。
type AdminAnonymous struct {
	Enabled     bool       `json:"enabled"`
	Mode        string     `json:"mode"`
	Generation  domain.U64 `json:"generation"`
	Revision    domain.U64 `json:"revision"`
	Revocations uint32     `json:"revocations"`
}

// ETag は失効状態の変更だけに束縛し、通常のCookie発行による競合を避ける。
func (v AdminAnonymous) ETag() string {
	return fmt.Sprintf(`"anonymous:%d:%d"`, v.Revision, v.Revocations)
}
func (r *Repository) anonymousView() AdminAnonymous {
	return r.anonymousViewAt(domain.Time(time.Now().UnixNano()))
}

// anonymousViewAt は満了した個別失効を新しいreceiptの件数依存へ持ち越さない。
func (r *Repository) anonymousViewAt(now domain.Time) AdminAnonymous {
	if r.anonymous == nil {
		return AdminAnonymous{Mode: "off"}
	}
	count := uint32(0)
	for _, record := range r.anonymous.revoked {
		if record.Expires > now {
			count++
		}
	}
	return AdminAnonymous{true, r.anonymous.policy.modeAt(now), r.anonymous.policy.Generation, r.site.State().Rows["anon_policy:active"].Revision, count}
}
func (r *Repository) adminAnonymous(s adminauth.Session) (AdminAnonymous, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.authorizeAdmin(s, "site_admin", domain.ID{}); e != nil {
		return AdminAnonymous{}, e
	}
	return r.anonymousView(), nil
}

type anonymousAdminInput struct {
	Subject *domain.Hash `json:"subject_hmac"`
	Mode    string       `json:"mode,omitempty"`
}

// UnmarshalJSON は失効要求と必須モード要求を区別し、同時指定を拒否する。
func (v *anonymousAdminInput) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	if _, ok := fields["mode"]; ok {
		var input struct {
			Mode string `json:"mode"`
		}
		if e := strictjson.Decode(raw, &input); e != nil {
			return e
		}
		*v = anonymousAdminInput{Mode: input.Mode}
		if v.Mode != "required" {
			return errors.New("invalid anonymous mode")
		}
		return nil
	}
	var input struct {
		Subject *domain.Hash `json:"subject_hmac"`
	}
	if e := strictjson.Decode(raw, &input); e != nil {
		return e
	}
	*v = anonymousAdminInput{Subject: input.Subject}
	return nil
}

// MarshalJSON は失効要求と必須モード要求を独立した完全型として保存する。
func (v anonymousAdminInput) MarshalJSON() ([]byte, error) {
	if v.Mode != "" {
		return json.Marshal(struct {
			Mode string `json:"mode"`
		}{v.Mode})
	}
	return json.Marshal(struct {
		Subject *domain.Hash `json:"subject_hmac"`
	}{v.Subject})
}

type anonymousReceipt struct {
	Type    string         `json:"type"`
	ID      domain.ID      `json:"id"`
	Admin   domain.ID      `json:"admin_id"`
	Key     domain.Hash    `json:"request_key_hmac"`
	Request domain.Hash    `json:"request_hmac"`
	Result  AdminAnonymous `json:"result"`
	Created domain.Time    `json:"created_at_ns"`
	Expires domain.Time    `json:"expires_at_ns"`
}

func isAnonymousReceipt(raw []byte) bool {
	var head struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(raw, &head) == nil && head.Type == "anonymous_change"
}
func validateAnonymousReceipt(key string, old, next []byte) error {
	var v anonymousReceipt
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if v.Type != "anonymous_change" || key != v.Key.String() || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 || !v.Result.Enabled || v.Result.Mode != "required" || v.Result.Generation == 0 || v.Result.Revision == 0 || v.Result.Revocations > 200000 {
		return store.ErrCorrupt
	}
	if len(old) > 0 {
		var prior anonymousReceipt
		if e := strictjson.Decode(old, &prior); e != nil {
			return e
		}
		if prior.Expires > v.Created {
			return errors.New("anonymous receipt still active")
		}
	}
	return nil
}

// changeAnonymous はnil主体なら全体失効する。最近の再認証・CAS・24時間receiptを必須とし、保存後に全板の旧処理を排出する。
func (r *Repository) changeAnonymous(ctx context.Context, s adminauth.Session, input anonymousAdminInput, etag, key string) (AdminAnonymous, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.validateAnonymousChange(ctx, s, input, etag, key); e != nil {
		return AdminAnonymous{}, e
	}
	dedupKey, e := readPrivateKeyForAnonymous(r)
	if e != nil {
		return AdminAnonymous{}, e
	}
	defer clear(dedupKey[:])
	requestKey := identity.MAC(dedupKey[:], "oimo/admin-anonymous-key/v1", s.Admin[:], []byte(key))
	raw, _ := json.Marshal(input)
	request := identity.MAC(dedupKey[:], "oimo/admin-anonymous-change/v1", s.Admin[:], raw, []byte(etag))
	state := r.site.State()
	now := domain.Time(time.Now().UnixNano())
	if result, found, e := anonymousChangeRetry(state, requestKey, request, now); found || e != nil {
		return result, e
	}
	if etag != r.anonymousView().ETag() {
		return AdminAnonymous{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) || now > domain.Time(1<<63-1)-31*86400e9 {
		return AdminAnonymous{}, ErrPostingUnavailable
	}
	if input.Mode != "" {
		// 旧条件の受理を排出してから履歴の時刻を決める。enqueue前にサイトmutexを
		// 離した要求も、保存中は板の停止境界で拒否し、旧条件で境界後へ記録させない。
		for _, b := range r.posting {
			if _, e := b.worker.Submit(context.Background(), func() (any, error) {
				if b.stopped {
					return nil, ErrPostingUnavailable
				}
				b.stopped = true
				return nil, nil
			}); e != nil {
				r.stopped = true
				return AdminAnonymous{}, e
			}
		}
		now = domain.Time(time.Now().UnixNano())
		r.admission.mu.Lock()
		lastAccepted := r.admission.lastReserved
		r.admission.mu.Unlock()
		if now <= lastAccepted {
			r.resumeAnonymousBoards()
			return AdminAnonymous{}, ErrPostingUnavailable
		}
	}
	next, result, changes, reason, targets, e := r.prepareAnonymousChange(input, now, state.Seq+1)
	if e != nil {
		if input.Mode != "" {
			r.resumeAnonymousBoards()
		}
		return AdminAnonymous{}, e
	}
	receipt := anonymousReceipt{"anonymous_change", domain.NewID(), s.Admin, requestKey, request, result, now, now + 86400e9}
	if e := r.saveAnonymousChange(state, s, receipt, changes, reason, targets); e != nil {
		return AdminAnonymous{}, e
	}
	r.anonymous = next
	r.liveAnonymous.Store(next)
	r.admission.mu.Lock()
	r.admission.anonymous = &next.policy
	r.admission.mu.Unlock()
	// 確定後は要求取消でも配布境界を完了させる。板処理からサイトmutexへ戻る呼出しはない。
	for _, b := range r.posting {
		if _, e := b.worker.Submit(context.Background(), func() (any, error) {
			if input.Mode != "" {
				b.stopped = false
			}
			return nil, nil
		}); e != nil {
			r.stopped = true
			return AdminAnonymous{}, e
		}
	}
	return result, nil
}

// resumeAnonymousBoards は保存前の候補拒否時だけ一時停止を解除する。保存失敗時は呼ばない。
func (r *Repository) resumeAnonymousBoards() {
	for _, b := range r.posting {
		if _, e := b.worker.Submit(context.Background(), func() (any, error) { b.stopped = false; return nil, nil }); e != nil {
			r.stopped = true
		}
	}
}

// readPrivateKeyForAnonymous は既存用途鍵8を用いる。秘密値は要求・応答・監査へ入れない。
func readPrivateKeyForAnonymous(r *Repository) (domain.Hash, error) {
	// 板のdedup鍵も同じ導出だが、板なしのサイトでも操作可能にする。
	master, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if e != nil {
		return domain.Hash{}, e
	}
	defer clear(master)
	return identity.DeriveKey(master, "dedup", 8)
}

// validateAnonymousChange は保存前の認可・再認証・要求形式を確認する。サイトmutex必須。
func (r *Repository) validateAnonymousChange(ctx context.Context, s adminauth.Session, input anonymousAdminInput, etag, key string) error {
	if e := r.authorizeAdmin(s, "site_admin", domain.ID{}); e != nil {
		return e
	}
	if !s.Reauthenticated(time.Now()) {
		return &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
	}
	if r.anonymous == nil {
		return &adminFailure{status: 422, code: "ANONYMOUS_NOT_ENABLED"}
	}
	if !adminRequestKey.MatchString(key) {
		return &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	if input.Subject != nil && *input.Subject == (domain.Hash{}) {
		return &adminFailure{status: 422, code: "INVALID_SUBJECT"}
	}
	if input.Mode != "" && input.Subject != nil {
		return &adminFailure{status: 422, code: "INVALID_MODE"}
	}
	if input.Mode != "" && input.Mode != "required" {
		return &adminFailure{status: 422, code: "COOKIE_REQUIRED"}
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return nil
}

// anonymousChangeRetry はCASより先に24時間の固定結果を返す。
func anonymousChangeRetry(state store.ControlState, requestKey, request domain.Hash, now domain.Time) (AdminAnonymous, bool, error) {
	if row, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var receipt anonymousReceipt
		if e := strictjson.Decode(row.Value, &receipt); e != nil {
			return AdminAnonymous{}, false, e
		}
		if receipt.Created > now {
			return AdminAnonymous{}, false, ErrPostingUnavailable
		}
		if receipt.Expires > now {
			if receipt.Request != request {
				return AdminAnonymous{}, false, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			return receipt.Result, true, nil
		}
	}
	return AdminAnonymous{}, false, nil
}

// prepareAnonymousChange は現在の不変状態から候補を作る。保存前に稼働状態を改変しない。
func (r *Repository) prepareAnonymousChange(input anonymousAdminInput, now domain.Time, seq domain.U64) (*anonymousState, AdminAnonymous, []store.Mutation, string, []string, error) {
	next := &anonymousState{policy: r.anonymous.policy, key: r.anonymous.key, revoked: maps.Clone(r.anonymous.revoked)}
	changes := []store.Mutation{}
	reason := "anonymous_revoke"
	targets := []string{}
	result := r.anonymousViewAt(now)
	if input.Mode != "" {
		if input.Mode == next.policy.modeAt(now) {
			return next, result, changes, "anonymous_mode_update", targets, nil
		}
		return nil, AdminAnonymous{}, nil, "", nil, &adminFailure{status: 422, code: "COOKIE_REQUIRED"}
	} else if input.Subject == nil {
		if next.policy.Generation == ^domain.U64(0) {
			return nil, AdminAnonymous{}, nil, "", nil, ErrPostingUnavailable
		}
		next.policy.Generation++
		changes = append(changes, mutation("anon_policy", "active", next.policy, nil))
		reason = "anonymous_revoke_all"
		result.Generation = next.policy.Generation
		result.Revision = seq
	} else if _, ok := next.revoked[*input.Subject]; !ok {
		if len(next.revoked) >= 200000 {
			return nil, AdminAnonymous{}, nil, "", nil, ErrPostingUnavailable
		}
		v := tokenRevocation{domain.NewID(), *input.Subject, 4, next.policy.Generation, now, now + 31*86400e9, "local_admin"}
		changes = append(changes, mutation("token_revocation", input.Subject.String(), v, nil))
		next.revoked[*input.Subject] = v
		result.Revocations++
		targets = append(targets, v.ID.String())
	}
	return next, result, changes, reason, targets, nil
}

// saveAnonymousChange は失効・最低reader版・監査・結果receiptを同じframeでSyncする。
func (r *Repository) saveAnonymousChange(state store.ControlState, s adminauth.Session, receipt anonymousReceipt, changes []store.Mutation, reason string, targets []string) error {
	var site siteState
	if e := strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil {
		return e
	}
	site.MinimumReader = max(site.MinimumReader, 20)
	changes = append(changes, mutation("site", "state", site, nil), mutation("admin_receipt", receipt.Key.String(), receipt, nil))
	for i := range changes {
		changes[i].ExpectedRevision = state.Rows[changes[i].Collection+":"+changes[i].Key].Revision
	}
	keyID := uint32(8)
	op := store.ControlOperation{Schema: 1, Seq: state.Seq + 1, ExpectedSeq: state.Seq, Committed: receipt.Created, Actor: domain.Actor{Kind: "admin", ID: &s.Admin, Reason: reason, Request: &receipt.Request, Idempotency: &receipt.Key, KeyID: &keyID}, Mutations: changes, Result: store.ControlResult{Code: reason, Targets: targets, RequestKey: &receipt.Key, Request: &receipt.Request, KeyID: &keyID, Expires: &receipt.Expires}}
	encoded, e := json.Marshal(op)
	if e != nil {
		return e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Seq), Records: []store.Record{{ID: receipt.ID, JSON: encoded}}})
	if e != nil {
		return e
	}
	if r.site.Append(frame).Status != store.Durable {
		r.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: receipt.ID}
	}
	return nil
}
