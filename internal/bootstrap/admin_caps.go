// キャップ発行・停止を担当板認可、固定再送、CAS、投稿排出、耐久保存へ接続する。
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"sort"
	"strings"
	"time"
)

type capInput struct {
	Name        string      `json:"display_name"`
	Boards      []domain.ID `json:"board_ids"`
	Permissions []string    `json:"permissions"`
	Expires     domain.Time `json:"expires_at_ns"`
}
type capReceipt struct {
	Type    string      `json:"type"`
	ID      domain.ID   `json:"id"`
	Admin   domain.ID   `json:"admin_id"`
	Key     domain.Hash `json:"request_key_hmac"`
	Request domain.Hash `json:"request_hmac"`
	Result  AdminCap    `json:"result"`
	Created domain.Time `json:"created_at_ns"`
	Expires domain.Time `json:"expires_at_ns"`
}

func isCapReceipt(raw []byte) bool {
	var v struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(raw, &v) == nil && v.Type == "cap_change"
}
func validateCapReceipt(key string, old, next json.RawMessage) error {
	var v capReceipt
	if strictjson.Decode(next, &v) != nil || v.Type != "cap_change" || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || key != v.Key.String() || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 {
		return store.ErrCorrupt
	}
	x := capValue{ID: v.Result.ID, Name: v.Result.Name, Secret: domain.Hash{1}, KeyID: 9, Boards: v.Result.Boards, Permissions: v.Result.Permissions, Enabled: true, Revision: 1, Created: 1, Expires: 2}
	if validateCapState(x) != nil || v.Result.Revision != 1 && v.Result.Revision != 2 || v.Result.Enabled != (v.Result.Revision == 1) || v.Result.Expires < 0 {
		return store.ErrCorrupt
	}
	if len(old) > 0 {
		var p capReceipt
		if strictjson.Decode(old, &p) != nil || p.Expires > v.Created {
			return store.ErrCorrupt
		}
	}
	return nil
}
func capListETag(seq domain.U64) string { return fmt.Sprintf(`"caps:%d"`, seq) }
func (r *Repository) adminCaps(s adminauth.Session) ([]AdminCap, domain.U64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, e := r.currentCapAdministrator(s)
	if e != nil {
		return nil, 0, e
	}
	scope := newCapScope(a)
	reg, e := loadCapRegistry(r.site.State())
	if e != nil {
		return nil, 0, e
	}
	rows := []AdminCap{}
	for _, v := range reg.Records {
		if scope.allows(v.Boards) {
			rows = append(rows, capView(v))
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID.String() < rows[j].ID.String() })
	return rows, scopedCapRevision(scope, reg), nil
}

// changeCap は秘密を初回確定応答だけに返す。成功済み再送は結果のみ返し、秘密を再表示しない。
func (r *Repository) changeCap(s adminauth.Session, target domain.ID, input capInput, etag, key string) (AdminCap, string, error) {
	return r.changeCapOperation(s, target, input, etag, key, false, false)
}

// changeCapOperation は旧資格停止と再発行を同じframeへ保存する。updating時だけ入力で資格条件を変更する。
func (r *Repository) changeCapOperation(s adminauth.Session, target domain.ID, input capInput, etag, key string, reset, updating bool) (AdminCap, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fail := func(e error) (AdminCap, string, error) { return AdminCap{}, "", e }
	a, e := r.currentCapAdministrator(s)
	if e != nil {
		return fail(e)
	}
	scope := newCapScope(a)
	if updating && (!reset || target == (domain.ID{})) {
		return fail(&adminFailure{status: 400, code: "INVALID_CAP_UPDATE"})
	}
	if !adminRequestKey.MatchString(key) {
		return fail(&adminFailure{status: 400, code: "INVALID_REQUEST_KEY"})
	}
	if etag == "" {
		return fail(&adminFailure{status: 428, code: "REVISION_REQUIRED"})
	}
	sort.Slice(input.Boards, func(i, j int) bool { return input.Boards[i].String() < input.Boards[j].String() })
	sort.Strings(input.Permissions)
	state := r.site.State()
	reg, e := loadCapRegistry(state)
	if e != nil {
		return fail(e)
	}
	boards := input.Boards
	if target != (domain.ID{}) {
		v, ok := reg.Records[target]
		if !ok {
			return fail(&adminFailure{status: 404, code: "CAP_NOT_FOUND"})
		}
		boards = v.Boards
	}
	if !scope.allows(boards) {
		if target != (domain.ID{}) {
			return fail(&adminFailure{status: 404, code: "CAP_NOT_FOUND"})
		}
		return fail(&adminFailure{status: 403, code: "BOARD_SCOPE_DENIED"})
	}
	if updating && !scope.allows(input.Boards) {
		return fail(&adminFailure{status: 403, code: "BOARD_SCOPE_DENIED"})
	}
	dedup, e := readPrivateKeyForAnonymous(r)
	if e != nil {
		return fail(e)
	}
	defer clear(dedup[:])
	raw, e := json.Marshal(input)
	if e != nil {
		return fail(e)
	}
	requestKey := identity.MAC(dedup[:], "oimo/admin-cap-key/v1", s.Admin[:], []byte(key))
	request := identity.MAC(dedup[:], "oimo/admin-cap-change/v1", s.Admin[:], target[:], []byte(etag), raw)
	if updating {
		request = identity.MAC(dedup[:], "oimo/admin-cap-update/v1", request[:])
	} else if reset {
		request = identity.MAC(dedup[:], "oimo/admin-cap-reset/v1", request[:])
	}
	now := domain.Time(time.Now().UnixNano())
	if row, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var old capReceipt
		if !isCapReceipt(row.Value) || strictjson.Decode(row.Value, &old) != nil {
			return fail(store.ErrCorrupt)
		}
		if old.Created > now {
			return fail(ErrPostingUnavailable)
		}
		if now < old.Expires {
			if old.Request != request {
				return fail(&adminFailure{status: 409, code: "REQUEST_CONFLICT"})
			}
			return old.Result, "", nil
		}
	}
	var value capValue
	var replaced *capValue
	secret := ""
	if target == (domain.ID{}) {
		if etag != capListETag(scopedCapRevision(scope, reg)) {
			return fail(&adminFailure{status: 412, code: "REVISION_CONFLICT"})
		}
		if len(reg.Records) >= 10000 {
			return fail(&adminFailure{status: 503, code: "CAP_CAPACITY"})
		}
		value, secret, e = r.newCapValue(input, now)
		if e != nil {
			return fail(e)
		}
	} else {
		value = reg.Records[target]
		if etag != capView(value).ETag() {
			return fail(&adminFailure{status: 412, code: "REVISION_CONFLICT"})
		}
		if !value.Enabled {
			return fail(&adminFailure{status: 409, code: "CAP_REVOKED"})
		}
	}
	receipts := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			receipts++
		}
	}
	if receipts >= 200000 || state.Seq == ^domain.U64(0) || now > domain.Time(1<<63-1)-86400e9 {
		return fail(ErrPostingUnavailable)
	}
	lastAccepted, e := r.freezeCapBoards(target)
	if e != nil {
		return fail(e)
	}
	now = domain.Time(time.Now().UnixNano())
	if target != (domain.ID{}) && now <= lastAccepted {
		r.resumeAnonymousBoards()
		return fail(ErrPostingUnavailable)
	}
	if target == (domain.ID{}) {
		value.Created = now
		if validateCapState(value) != nil {
			r.resumeAnonymousBoards()
			return fail(&adminFailure{status: 422, code: "INVALID_CAP"})
		}
	} else {
		value.Enabled = false
		value.Revision++
		value.Revoked = &now
		if reset {
			if len(reg.Records) >= 10000 || !updating && value.Expires != 0 && value.Expires <= now {
				r.resumeAnonymousBoards()
				return fail(&adminFailure{status: 409, code: "CAP_EXPIRED_OR_CAPACITY"})
			}
			old := value
			replaced = &old
			replacement := capInput{old.Name, old.Boards, old.Permissions, old.Expires}
			if updating {
				replacement = input
			}
			value, secret, e = r.newCapValue(replacement, now)
			if e != nil {
				r.resumeAnonymousBoards()
				return fail(e)
			}
		}
	}
	view := capView(value)
	if e = r.persistCapChange(s, state, target, value, requestKey, request, now, replaced, updating); e != nil {
		r.stopped = true
		return fail(e)
	}
	reg, e = loadCapRegistry(r.site.State())
	if e != nil {
		r.stopped = true
		return fail(e)
	}
	r.liveCaps.Store(reg)
	r.resumeAnonymousBoards()
	if r.stopped {
		return fail(ErrPostingUnavailable)
	}
	return view, secret, nil
}

// newCapValue は有効な担当範囲だけへ資格を作り、原秘密は返却値以外に保存しない。
func (r *Repository) newCapValue(input capInput, now domain.Time) (capValue, string, error) {
	value := capValue{ID: domain.NewID(), Name: input.Name, KeyID: 9, Boards: slices.Clone(input.Boards), Permissions: slices.Clone(input.Permissions), Enabled: true, Expires: input.Expires, Revision: 1, Created: now}
	for _, id := range value.Boards {
		if r.boards[id] == nil {
			return capValue{}, "", &adminFailure{status: 422, code: "INVALID_BOARD"}
		}
	}
	bytes := make([]byte, 32)
	if _, e := rand.Read(bytes); e != nil {
		return capValue{}, "", e
	}
	secret := base64.RawURLEncoding.EncodeToString(bytes)
	clear(bytes)
	master, e := readCapKey(r)
	if e != nil {
		return capValue{}, "", e
	}
	value.Secret = capSecret(master, value.ID, secret)
	clear(master[:])
	if validateCapState(value) != nil {
		return capValue{}, "", &adminFailure{status: 422, code: "INVALID_CAP"}
	}
	return value, secret, nil
}

// freezeCapBoards は所有列で先行投稿を排出する。部分停止に失敗した場合は全体を停止する。
func (r *Repository) freezeCapBoards(target domain.ID) (domain.Time, error) {
	lastAccepted := domain.Time(0)
	for _, b := range r.posting {
		if _, e := b.worker.Submit(context.Background(), func() (any, error) {
			if b.stopped {
				return nil, ErrPostingUnavailable
			}
			b.stopped = true
			lastAccepted = max(lastAccepted, b.capCommitted[target])
			return nil, nil
		}); e != nil {
			r.stopped = true
			return 0, e
		}
	}
	return lastAccepted, nil
}

// persistCapChange はreader境界・資格・再送結果を一つの監査付き同期保存に含める。
func (r *Repository) persistCapChange(s adminauth.Session, state store.ControlState, target domain.ID, value capValue, requestKey, request domain.Hash, now domain.Time, replaced *capValue, updating bool) error {
	view := capView(value)
	id := domain.NewID()
	receipt := capReceipt{"cap_change", id, s.Admin, requestKey, request, view, now, now + 86400e9}
	var site siteState
	if e := strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil {
		return e
	}
	site.MinimumReader = max(site.MinimumReader, 35)
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("cap", value.ID.String(), value, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
	for i := range changes {
		changes[i].ExpectedRevision = state.Rows[changes[i].Collection+":"+changes[i].Key].Revision
	}
	if replaced != nil {
		change := mutation("cap", replaced.ID.String(), *replaced, nil)
		change.ExpectedRevision = state.Rows["cap:"+replaced.ID.String()].Revision
		changes = append(changes, change)
	}
	reason := "cap_create"
	if target != (domain.ID{}) {
		reason = "cap_revoke"
	}
	if replaced != nil {
		reason = "cap_reset"
		if updating {
			reason = "cap_update"
		}
	}
	keyID := uint32(8)
	op := store.ControlOperation{Schema: 1, Seq: state.Seq + 1, ExpectedSeq: state.Seq, Committed: now, Actor: domain.Actor{Kind: "admin", ID: &s.Admin, Reason: reason, Request: &request, Idempotency: &requestKey, KeyID: &keyID}, Mutations: changes, Result: store.ControlResult{Code: "cap_saved", Targets: []string{value.ID.String()}, RequestKey: &requestKey, Request: &request, KeyID: &keyID, Expires: &receipt.Expires}}
	if replaced != nil {
		op.Result.Targets = append(op.Result.Targets, replaced.ID.String())
	}
	encoded, e := json.Marshal(op)
	if e != nil {
		return e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Seq), Records: []store.Record{{ID: id, JSON: encoded}}})
	if e != nil {
		return e
	}
	result := r.site.Append(frame)
	if result.Status != store.Durable {
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	return nil
}
