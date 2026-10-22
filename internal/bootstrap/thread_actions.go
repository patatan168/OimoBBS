// スレッド管理の固定frameを本文なしの先行intentへ保存し、所有列で再開する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// AdminThreadAction は操作別の入力。Targetはmove_link、Policyはupdate_policyだけで使用する。
type AdminThreadAction struct {
	Kind   string         `json:"kind"`
	Target string         `json:"target"`
	Policy *domain.Policy `json:"policy"`
}

// ThreadActionRecord は固定操作と再開位置。既存本文・接続情報は複製しない。
type ThreadActionRecord struct {
	ID        domain.ID    `json:"id"`
	Board     domain.ID    `json:"board_id"`
	Thread    domain.U64   `json:"thread_key"`
	Expected  domain.U64   `json:"expected_thread_seq"`
	Operation domain.ID    `json:"operation_id"`
	Kind      string       `json:"kind"`
	Created   domain.Time  `json:"created_at_ns"`
	Expires   domain.Time  `json:"thread_expires_at_ns"`
	Actor     domain.Actor `json:"actor"`
	Frame     string       `json:"frame"`
	Digest    domain.Hash  `json:"frame_sha256"`
	Phase     string       `json:"phase"`
}

func validateThreadAction(key string, old, next json.RawMessage) error {
	var v ThreadActionRecord
	if strictjson.Decode(next, &v) != nil || key != v.ID.String() || v.ID == (domain.ID{}) || v.Board == (domain.ID{}) || v.Thread == 0 || v.Operation == (domain.ID{}) || v.Expected == 0 || v.Expected == ^domain.U64(0) || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires <= v.Created || v.Actor.Kind != "admin" || v.Actor.Validate() != nil || v.Actor.KeyID == nil || *v.Actor.KeyID != 8 || v.Actor.Reason != "thread_"+v.Kind {
		return store.ErrCorrupt
	}
	if v.Kind != "stop" && v.Kind != "archive" && v.Kind != "move_link" && v.Kind != "update_policy" {
		return store.ErrCorrupt
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(v.Frame)
	if err != nil || len(raw) > 64<<10 || base64.StdEncoding.EncodeToString(raw) != v.Frame || sha256.Sum256(raw) != v.Digest {
		return store.ErrCorrupt
	}
	f, n, err := store.ReadFrame(bytes.NewReader(raw))
	if err != nil || n != int64(len(raw)) || len(f.Records) != 1 || f.Records[0].ID != v.Operation || f.FirstSeq != uint64(v.Expected+1) {
		return store.ErrCorrupt
	}
	op, err := domain.ParseOperation(f.Records[0].JSON)
	if err != nil || op.Type != v.Kind || op.Committed != v.Created || op.Revision != v.Expected+1 || op.Dedup != nil || !reflect.DeepEqual(op.Actor, v.Actor) {
		return store.ErrCorrupt
	}
	if v.Phase != "intent" && v.Phase != "applied" && v.Phase != "expired" {
		return store.ErrCorrupt
	}
	if len(old) == 0 {
		if v.Phase != "intent" {
			return store.ErrCorrupt
		}
		return nil
	}
	var prior ThreadActionRecord
	if strictjson.Decode(old, &prior) != nil || prior.Phase != "intent" || v.Phase == "intent" {
		return store.ErrCorrupt
	}
	prior.Phase = v.Phase
	if !reflect.DeepEqual(prior, v) {
		return store.ErrCorrupt
	}
	return nil
}

func (v AdminThreadAction) validate() error {
	switch v.Kind {
	case "stop", "archive":
		if v.Target != "" || v.Policy != nil {
			return domain.ErrOperation
		}
	case "move_link":
		if len(v.Target) == 0 || len(v.Target) > 2048 || v.Policy != nil {
			return domain.ErrOperation
		}
	case "update_policy":
		// 現在の投稿実装が証明できない表示・コマンドを設定だけで有効にしない。
		if v.Target != "" || v.Policy == nil || v.Policy.Validate() != nil || v.Policy.Pinned || v.Policy.AutoNext || v.Policy.UserPostLimit > 10000 {
			return domain.ErrOperation
		}
	default:
		return domain.ErrOperation
	}
	return nil
}

// ChangeThread はCASを確認してintentをSyncし、取消に左右されず同じ固定操作を確定する。
func (r *Repository) ChangeThread(ctx context.Context, s adminauth.Session, owner domain.ID, key uint64, edit AdminThreadAction, etag, requestID string) (ThreadActionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	role := "board_admin"
	if edit.Kind == "stop" {
		role = "moderator"
	}
	if err := r.authorizeAdmin(s, role, owner); err != nil {
		return ThreadActionRecord{}, err
	}
	if !adminRequestKey.MatchString(requestID) {
		return ThreadActionRecord{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if edit.validate() != nil {
		return ThreadActionRecord{}, &adminFailure{status: 422, code: "INVALID_THREAD_ACTION"}
	}
	b := r.posting[owner]
	if b == nil {
		return ThreadActionRecord{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	raw, _ := json.Marshal(edit)
	requestKey := identity.MAC(b.dedupKey[:], "oimo/thread-action-key/v1", s.Admin[:], owner[:], []byte(fmt.Sprint(key)), []byte(requestID))
	request := identity.MAC(b.dedupKey[:], "oimo/thread-action-request/v1", requestKey[:], raw, []byte(etag))
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return ThreadActionRecord{}, err
	}
	requiredReader := uint32(25)
	if edit.Policy != nil && (edit.Policy.SlipMode != "none" || edit.Policy.RequireSlipHash || edit.Policy.RequirePublicIP) {
		requiredReader = 29
	}
	if site.MinimumReader < requiredReader {
		site.MinimumReader = requiredReader
		if err := appendControl(r.site, "thread_actions_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{owner.String()}); err != nil {
			r.stopped = true
			return ThreadActionRecord{}, err
		}
	}
	command := threadActionCommand{Admin: s.Admin, Key: key, Edit: edit, ETag: etag, RequestKey: requestKey, Request: request, SiteRevision: site.PublicRevision}
	value, err := b.worker.Submit(ctx, func() (any, error) { return b.changeThreadAction(command) })
	if err != nil {
		return ThreadActionRecord{}, err
	}
	return cloneThreadAction(value.(ThreadActionRecord)), nil
}

type threadActionCommand struct {
	Admin               domain.ID
	Key                 uint64
	Edit                AdminThreadAction
	ETag                string
	RequestKey, Request domain.Hash
	SiteRevision        domain.U64
}

// changeThreadAction は所有列で再送を先に解決し、新規候補だけを上限・CASへ通す。
func (b *postingBoard) changeThreadAction(command threadActionCommand) (any, error) {
	if b.stopped {
		return nil, ErrPostingUnavailable
	}
	if err := b.enableRetention(command.SiteRevision); err != nil {
		return nil, err
	}
	records, err := b.threadActions()
	if err != nil {
		return nil, err
	}
	now := domain.Time(b.clock().UnixNano())
	prior, count, err := matchThreadAction(records, command, now)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return b.resumeThreadAction(*prior)
	}
	if len(records) >= 1024 || count >= 128 {
		return nil, &adminFailure{status: 503, code: "THREAD_ACTION_CAPACITY"}
	}
	v, p, err := b.prepareThreadAction(command, now)
	if err != nil {
		return nil, err
	}
	return b.commitThreadAction(v, p)
}

func matchThreadAction(records []ThreadActionRecord, command threadActionCommand, now domain.Time) (*ThreadActionRecord, int, error) {
	count := 0
	for _, prior := range records {
		if uint64(prior.Thread) != command.Key {
			continue
		}
		count++
		if prior.Actor.Idempotency == nil || *prior.Actor.Idempotency != command.RequestKey || prior.Phase != "intent" && now >= prior.Created+86400e9 {
			continue
		}
		if now < prior.Created {
			return nil, count, ErrPostingUnavailable
		}
		if prior.Actor.Request == nil || *prior.Actor.Request != command.Request {
			return nil, count, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
		}
		return &prior, count, nil
	}
	return nil, count, nil
}

// prepareThreadAction は保存値を生成する前に対象CAS・現行設定・状態遷移を検算する。
func (b *postingBoard) prepareThreadAction(command threadActionCommand, now domain.Time) (ThreadActionRecord, *app.PostingLog, error) {
	key, edit, etag, requestKey, request := command.Key, command.Edit, command.ETag, command.RequestKey, command.Request
	p := b.threads[key]
	if p == nil {
		return ThreadActionRecord{}, nil, &adminFailure{status: 404, code: "THREAD_NOT_FOUND"}
	}
	seq, expires, _, _, err := p.ThreadActionState()
	if err != nil {
		return ThreadActionRecord{}, nil, err
	}
	if etag != fmt.Sprintf(`"%s:%d:%d"`, b.owner, key, seq) {
		return ThreadActionRecord{}, nil, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	var board boardValue
	if err := strictjson.Decode(b.control.State().Rows["board:state"].Value, &board); err != nil {
		return ThreadActionRecord{}, nil, err
	}
	kid := uint32(8)
	v := ThreadActionRecord{ID: domain.NewID(), Board: b.owner, Thread: domain.U64(key), Expected: seq, Operation: domain.NewID(), Kind: edit.Kind, Created: now, Expires: expires, Actor: domain.Actor{Kind: "admin", ID: &command.Admin, Reason: "thread_" + edit.Kind, Request: &request, Idempotency: &requestKey, KeyID: &kid}, Phase: "intent"}
	settings, err := b.threadSettings()
	if err != nil {
		return ThreadActionRecord{}, nil, err
	}
	ending := settings.Settings.First
	if !ending.Enabled {
		ending = EndingSettings{Name: "OimoBBS", Body: "このスレッドは終了しました。"}
	}
	frame, err := p.PrepareThreadAction(app.ThreadActionInput{ID: v.Operation, Kind: edit.Kind, Target: edit.Target, Policy: edit.Policy, Ending: domain.Post{Name: ending.Name, Mail: ending.Mail, Body: ending.Body}, Expected: seq, Actor: v.Actor, Versions: domain.Versions{Site: command.SiteRevision, Board: board.Settings.Version}, Now: now})
	if err != nil {
		return ThreadActionRecord{}, nil, &adminFailure{status: 422, code: "INVALID_THREAD_ACTION"}
	}
	v.Frame, v.Digest = base64.StdEncoding.EncodeToString(frame), sha256.Sum256(frame)
	return v, p, nil
}

// commitThreadAction は先行intent以後を取消から切り離して同じ固定操作へ進める。
func (b *postingBoard) commitThreadAction(v ThreadActionRecord, p *app.PostingLog) (ThreadActionRecord, error) {
	p.BlockPublic(true)
	if err := b.saveThreadAction(v); err != nil {
		b.stopped = true
		return v, err
	}
	if err := b.afterDeletion("action:intent"); err != nil {
		b.stopped = true
		return v, err
	}
	return b.resumeThreadAction(v)
}

// threadActions は起動時にだけ所有ログを走査し、以降は有界な確定済み集合を返す。
func (b *postingBoard) threadActions() ([]ThreadActionRecord, error) {
	if b.threadActionRecords != nil {
		records := make([]ThreadActionRecord, 0, len(b.threadActionRecords))
		for _, v := range b.threadActionRecords {
			records = append(records, v)
		}
		return records, nil
	}
	records := []ThreadActionRecord{}
	counts := map[uint64]int{}
	for key, log := range b.deletions {
		for name, row := range log.State().Rows {
			if !strings.HasPrefix(name, "thread_action:") {
				continue
			}
			var v ThreadActionRecord
			if strictjson.Decode(row.Value, &v) != nil || v.Board != b.owner || uint64(v.Thread) != key {
				return nil, store.ErrCorrupt
			}
			counts[key]++
			if counts[key] > 128 || len(records) >= 1024 {
				return nil, store.ErrCorrupt
			}
			records = append(records, v)
		}
	}
	b.threadActionRecords = map[domain.ID]ThreadActionRecord{}
	for _, v := range records {
		b.threadActionRecords[v.ID] = v
	}
	return records, nil
}

// saveThreadAction はkind3の同一所有ログへSyncし、成功した現在値だけを参照集合へ反映する。
func (b *postingBoard) saveThreadAction(v ThreadActionRecord) error {
	b.deletionEpoch.Add(1)
	key := uint64(v.Thread)
	log := b.deletions[key]
	state := store.ControlState{}
	if log != nil {
		state = log.State()
	}
	change := mutation("thread_action", v.ID.String(), v, nil)
	change.ExpectedRevision = state.Rows["thread_action:"+v.ID.String()].Revision
	op := store.ControlOperation{Schema: 1, Seq: state.Seq + 1, ExpectedSeq: state.Seq, Committed: domain.Time(b.clock().UnixNano()), Actor: v.Actor, Mutations: []store.Mutation{change}, Result: store.ControlResult{Code: "thread_action_saved", Targets: []string{v.ID.String()}}}
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	frame, err := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Seq), Records: []store.Record{{ID: domain.NewID(), JSON: raw}}})
	if err != nil {
		return err
	}
	if log != nil {
		result := log.Append(frame)
		if result.Status != store.Durable {
			return errors.Join(ErrPostingUnavailable, result.Err)
		}
		if b.threadActionRecords != nil {
			b.threadActionRecords[v.ID] = v
		}
		return nil
	}
	parent := filepath.Join(b.root, "expiry", b.owner.String())
	if err := ensurePostingDirectory(parent); err != nil {
		return err
	}
	log, err = store.CreateControl(filepath.Join(parent, fmt.Sprint(key)), store.Header{Kind: 3, Owner: b.owner, Key: key, Generation: 1}, frame, validateDeletion)
	if err == nil {
		b.deletions[key] = log
		if b.threadActionRecords != nil {
			b.threadActionRecords[v.ID] = v
		}
	}
	return err
}

// resumeThreadAction は完全frameと署名証拠を照合し、未確定操作の再開か期限終了を保存する。
func (b *postingBoard) resumeThreadAction(v ThreadActionRecord) (saved ThreadActionRecord, err error) {
	defer func() {
		if err != nil {
			b.stopped = true
			if p := b.threads[uint64(v.Thread)]; p != nil {
				p.BlockPublic(true)
			}
		}
	}()
	p := b.threads[uint64(v.Thread)]
	if p == nil {
		return v, app.ErrEvidenceGap
	}
	_, expires, _, present := p.RetentionState()
	if !present || expires != v.Expires {
		return v, app.ErrEvidenceGap
	}
	frame, err := base64.StdEncoding.Strict().DecodeString(v.Frame)
	if err != nil {
		return v, err
	}
	if digest, present := p.AdministrativeDigest(v.Operation); present && digest != v.Digest {
		return v, app.ErrEvidenceGap
	}
	applied := p.AdministrativeApplied(v.Operation, v.Expected+1, frame)
	if v.Phase == "applied" {
		if !applied {
			return v, app.ErrEvidenceGap
		}
		return v, nil
	}
	if v.Phase == "expired" {
		if applied || domain.Time(b.clock().UnixNano()) < v.Expires {
			return v, app.ErrEvidenceGap
		}
		return v, nil
	}
	p.BlockPublic(true)
	fail := func(err error) (ThreadActionRecord, error) { b.stopped = true; return v, err }
	now := domain.Time(b.clock().UnixNano())
	if now < v.Created {
		return fail(ErrPostingUnavailable)
	}
	if !applied && now >= v.Expires {
		v.Phase = "expired"
		if err := b.saveThreadAction(v); err != nil {
			return fail(err)
		}
		p.RestoreExpired()
		return v, nil
	}
	if !applied {
		seq, expires, _, _, err := p.ThreadActionState()
		if err != nil || seq != v.Expected || expires != v.Expires {
			return fail(app.ErrEvidenceGap)
		}
		j, err := b.journal(time.Unix(0, int64(v.Created)))
		if err != nil {
			return fail(err)
		}
		if err = p.UseJournal(j); err != nil {
			return fail(err)
		}
		result := p.ApplyModeration(context.Background(), frame, now)
		if result.Status != store.Durable {
			return fail(errors.Join(app.ErrEvidenceGap, result.Err))
		}
	}
	if err := b.afterDeletion("action:thread"); err != nil {
		return fail(err)
	}
	v.Phase = "applied"
	if err := b.saveThreadAction(v); err != nil {
		return fail(err)
	}
	if err := b.afterDeletion("action:applied"); err != nil {
		return fail(err)
	}
	p.BlockPublic(false)
	return v, nil
}

// cloneThreadAction は呼出側の書換えが所有列内のActorへ伝わらないように返却値を分離する。
func cloneThreadAction(v ThreadActionRecord) ThreadActionRecord {
	if v.Actor.ID != nil {
		id := *v.Actor.ID
		v.Actor.ID = &id
	}
	if v.Actor.Request != nil {
		request := *v.Actor.Request
		v.Actor.Request = &request
	}
	if v.Actor.Idempotency != nil {
		key := *v.Actor.Idempotency
		v.Actor.Idempotency = &key
	}
	if v.Actor.KeyID != nil {
		key := *v.Actor.KeyID
		v.Actor.KeyID = &key
	}
	return v
}
