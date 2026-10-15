// 本文を持たない削除intentを先行保存し、同じ固定操作の再開を所有列へ接続する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type deletionBundle struct {
	ID     domain.ID   `json:"id"`
	Length domain.U64  `json:"length"`
	SHA    domain.Hash `json:"sha256"`
}

// DeletionRecord は公開停止と掃除の進捗。本文・接続元・タイトルは保存しない。
type DeletionRecord struct {
	ID              domain.ID            `json:"id"`
	Board           domain.ID            `json:"board_id"`
	Thread          domain.U64           `json:"thread_key"`
	Kind            string               `json:"kind"`
	Ranges          []app.RedactionRange `json:"ranges"`
	HideTitle       bool                 `json:"hide_title"`
	Expected        domain.U64           `json:"expected_thread_seq"`
	TargetOperation domain.ID            `json:"target_operation_id"`
	TargetSeq       *domain.U64          `json:"target_seq"`
	Format          uint32               `json:"format_version"`
	Phase           string               `json:"phase"`
	Created         domain.Time          `json:"created_at_ns"`
	Expires         domain.Time          `json:"thread_expires_at_ns"`
	CleanupDue      domain.Time          `json:"cleanup_due_at_ns"`
	Actor           domain.Actor         `json:"actor"`
	Versions        domain.Versions      `json:"policy_versions"`
	Audit           string               `json:"audit_transfer"`
	Carry           *deletionBundle      `json:"carry_bundle"`
	LastError       *string              `json:"last_error"`
}

func validateDeletion(collection, key string, old, next json.RawMessage) error {
	if collection == "reclamation" && key == "carry_retirement" {
		return validateCarryErasure(key, old, next)
	}
	if collection == "reclamation" && (key == "audit" || key == "audit_intent") {
		return validateThreadAuditTransfer(key, old, next)
	}
	if collection == "dedup_carry" || collection == "rate_carry" || collection == "reclamation" && key == "carry" {
		return validateBodyCarry(collection, key, old, next)
	}
	if collection == "reclamation" {
		return validateBodyReclamation(key, old, next)
	}
	if collection == "thread_action" {
		return validateThreadAction(key, old, next)
	}
	if collection == "copy_task" {
		return validateDeletionCopyTask(key, old, next)
	}
	if collection != "deletion" {
		return store.ErrCorrupt
	}
	var v DeletionRecord
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if key != v.ID.String() || v.Board == (domain.ID{}) || v.Thread == 0 || v.Expected == 0 || v.TargetOperation == (domain.ID{}) || v.Format != 1 || v.Actor.Validate() != nil || v.Versions.Site == 0 || v.Versions.Board == 0 || v.Versions.Thread == 0 || v.Created <= 0 || v.Expires <= 0 || v.Audit != "pending" && v.Audit != "complete" || v.Carry != nil || v.LastError != nil {
		return store.ErrCorrupt
	}
	if v.Kind == "expire" {
		if v.Actor.Kind != "system" || v.Actor.Reason != "thread_expire" || v.Created < v.Expires || v.Expires > domain.Time(1<<63-1)-300e9 || v.CleanupDue != v.Expires+300e9 || v.TargetSeq != nil {
			return store.ErrCorrupt
		}
	} else if v.Kind == "redact" || v.Kind == "hide" {
		if v.Actor.Kind != "admin" || v.Expires <= v.Created || v.Created > domain.Time(1<<63-1)-86400e9 || v.CleanupDue != v.Created+86400e9 || v.TargetSeq == nil || v.Expected == ^domain.U64(0) || *v.TargetSeq != v.Expected+1 {
			return store.ErrCorrupt
		}
	} else {
		return store.ErrCorrupt
	}
	if v.Kind != "redact" && (len(v.Ranges) != 0 || v.HideTitle) {
		return store.ErrCorrupt
	}
	var last, total uint32
	for _, r := range v.Ranges {
		if r.First == 0 || r.First <= last || r.Last < r.First || r.Last-r.First >= 256 || (r.Mode != "aboon" && r.Mode != "transparent") {
			return store.ErrCorrupt
		}
		total += r.Last - r.First + 1
		last = r.Last
	}
	if total > 256 || len(v.Ranges) > 256 || v.Kind == "redact" && total == 0 && !v.HideTitle {
		return store.ErrCorrupt
	}
	phases := map[string]int{"intent": 0, "public_stopped": 1, "applied": 2, "cleaning": 3}
	phase, ok := phases[v.Phase]
	if !ok {
		return store.ErrCorrupt
	}
	if len(old) == 0 {
		if phase != 0 || v.Audit != "pending" {
			return store.ErrCorrupt
		}
		return nil
	}
	var prior DeletionRecord
	if e := strictjson.Decode(old, &prior); e != nil {
		return e
	}
	if prior.Phase == v.Phase && prior.Audit == "pending" && v.Audit == "complete" && (v.Kind == "hide" || v.Kind == "expire") && phase >= 2 {
		prior.Audit = v.Audit
		if !reflect.DeepEqual(prior, v) {
			return store.ErrCorrupt
		}
		return nil
	}
	if phases[prior.Phase]+1 != phase {
		return store.ErrCorrupt
	}
	prior.Phase = v.Phase
	if !reflect.DeepEqual(prior, v) {
		return store.ErrCorrupt
	}
	return nil
}

// AdminModeration は認証済み管理入力。認可・CAS・HMAC・固定IDはRepositoryが生成する。
type AdminModeration struct {
	Kind      string               `json:"kind"`
	Ranges    []app.RedactionRange `json:"ranges"`
	HideTitle bool                 `json:"hide_title"`
}

// ModerateThread は削除intentの保存後に取消を受けず公開反映を確定する。
// Appliedは公開反映済みを表し、旧コピーの物理掃除完了を表さない。
func (r *Repository) ModerateThread(ctx context.Context, s adminauth.Session, owner domain.ID, key uint64, edit AdminModeration, etag, requestID string) (DeletionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	role := "moderator"
	if edit.Kind == "hide" {
		role = "board_admin"
	}
	if e := r.authorizeAdmin(s, role, owner); e != nil {
		return DeletionRecord{}, e
	}
	if !adminRequestKey.MatchString(requestID) {
		return DeletionRecord{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	b := r.posting[owner]
	if b == nil {
		return DeletionRecord{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	raw, e := json.Marshal(edit)
	if e != nil {
		return DeletionRecord{}, e
	}
	requestKey := identity.MAC(b.dedupKey[:], "oimo/moderation-key/v1", s.Admin[:], owner[:], []byte(fmt.Sprint(key)), []byte(requestID))
	request := identity.MAC(b.dedupKey[:], "oimo/moderation-request/v1", requestKey[:], raw, []byte(etag))
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return DeletionRecord{}, e
	}
	// 未対応readerが管理証拠を投稿として解釈しないよう、先に最低版を確定する。
	if site.MinimumReader < 16 {
		site.MinimumReader = 16
		if e = appendControl(r.site, "moderation_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{owner.String()}); e != nil {
			r.stopped = true
			return DeletionRecord{}, e
		}
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		return b.moderateThread(key, edit, etag, requestKey, request, s.Admin, "thread_moderation", site)
	})
	if e != nil {
		return DeletionRecord{}, e
	}
	return value.(DeletionRecord), nil
}

// moderateThread は認可済み削除を所有列で確定し、先行intentからの再送も解決する。
func (b *postingBoard) moderateThread(key uint64, edit AdminModeration, etag string, requestKey, request domain.Hash, actorID domain.ID, reason string, site siteState) (any, error) {
	if e := b.enableRetention(site.PublicRevision); e != nil {
		return nil, e
	}
	if b.stopped {
		return nil, ErrPostingUnavailable
	}
	log := b.deletions[key]
	if log != nil {
		for name, row := range log.State().Rows {
			if !strings.HasPrefix(name, "deletion:") {
				continue
			}
			var prior DeletionRecord
			if e := strictjson.Decode(row.Value, &prior); e != nil {
				return nil, e
			}
			if prior.Actor.Idempotency != nil && *prior.Actor.Idempotency == requestKey {
				now := domain.Time(b.clock().UnixNano())
				if prior.Created > now {
					return nil, ErrPostingUnavailable
				}
				if (prior.Phase == "applied" || prior.Phase == "cleaning") && now >= prior.Created+86400e9 {
					continue
				}
				if prior.Actor.Request == nil || *prior.Actor.Request != request {
					return nil, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
				}
				return b.resumeDeletion(prior)
			}
		}
	}
	p := b.threads[key]
	if p == nil {
		return nil, &adminFailure{status: 404, code: "THREAD_NOT_FOUND"}
	}
	seq, expires, e := p.ModerationState()
	if e != nil {
		return nil, e
	}
	if etag != fmt.Sprintf(`"%s:%d:%d"`, b.owner, key, seq) {
		return nil, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	if log != nil {
		for name, row := range log.State().Rows {
			if !strings.HasPrefix(name, "deletion:") {
				continue
			}
			var prior DeletionRecord
			if e := strictjson.Decode(row.Value, &prior); e != nil {
				return nil, e
			}
			if prior.Phase != "applied" && prior.Phase != "cleaning" {
				return nil, ErrPostingUnavailable
			}
		}
	}
	var boardState boardValue
	if e := strictjson.Decode(b.control.State().Rows["board:state"].Value, &boardState); e != nil {
		return nil, e
	}
	policy, ok := p.PostingPolicy(domain.Time(b.clock().UnixNano()))
	if !ok {
		return nil, ErrPostingUnavailable
	}
	now := domain.Time(b.clock().UnixNano())
	target := seq + 1
	kid := uint32(8)
	v := DeletionRecord{ID: domain.NewID(), Board: b.owner, Thread: domain.U64(key), Kind: edit.Kind, Ranges: append([]app.RedactionRange{}, edit.Ranges...), HideTitle: edit.HideTitle, Expected: seq, TargetOperation: domain.NewID(), TargetSeq: &target, Format: 1, Phase: "intent", Created: now, Expires: expires, CleanupDue: now + 86400e9, Actor: domain.Actor{Kind: "admin", ID: &actorID, Reason: reason, Request: &request, Idempotency: &requestKey, KeyID: &kid}, Versions: domain.Versions{Site: site.PublicRevision, Board: boardState.Settings.Version, Thread: policy.Version}, Audit: "pending"}
	if _, e = p.PrepareModeration(v.input()); e != nil {
		return nil, &adminFailure{status: 422, code: "INVALID_MODERATION"}
	}
	if e = b.saveDeletion(v); e != nil {
		p.BlockPublic(true)
		b.stopped = true
		return nil, e
	}
	p.BlockPublic(true)
	if e := b.afterDeletion("deletion:intent"); e != nil {
		b.stopped = true
		return nil, e
	}
	return b.resumeDeletion(v)
}

func (v DeletionRecord) input() app.ModerationInput {
	return app.ModerationInput{ID: v.TargetOperation, DeletionID: v.ID, Type: v.Kind, Ranges: v.Ranges, HideTitle: v.HideTitle, Expected: v.Expected, Actor: v.Actor, Versions: v.Versions, Now: v.Created}
}

// saveDeletion は単一削除行の確定をkind3のWALへ同期保存する。
func (b *postingBoard) saveDeletion(v DeletionRecord) error {
	// 失敗も旧境界の設置を失効させる。未知Syncは公開とwriterを閉じる。
	b.deletionEpoch.Add(1)
	log := b.deletions[uint64(v.Thread)]
	state := store.ControlState{}
	if log != nil {
		state = log.State()
	}
	change := mutation("deletion", v.ID.String(), v, nil)
	change.ExpectedRevision = state.Rows["deletion:"+v.ID.String()].Revision
	op := store.ControlOperation{Schema: 1, Seq: state.Seq + 1, ExpectedSeq: state.Seq, Committed: domain.Time(b.clock().UnixNano()), Actor: v.Actor, Mutations: []store.Mutation{change}, Result: store.ControlResult{Code: "deletion_saved", Targets: []string{v.ID.String()}}}
	raw, e := json.Marshal(op)
	if e != nil {
		return e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Seq), Records: []store.Record{{ID: domain.NewID(), JSON: raw}}})
	if e != nil {
		return e
	}
	if log != nil {
		result := log.Append(frame)
		if result.Status != store.Durable {
			return errors.Join(ErrPostingUnavailable, result.Err)
		}
		return nil
	}
	parent := filepath.Join(b.root, "expiry", b.owner.String())
	if e = ensurePostingDirectory(parent); e != nil {
		return e
	}
	log, e = store.CreateControl(filepath.Join(parent, fmt.Sprint(v.Thread)), store.Header{Kind: 3, Owner: b.owner, Key: uint64(v.Thread), Generation: 1}, frame, validateDeletion)
	if e != nil {
		return e
	}
	b.deletions[uint64(v.Thread)] = log
	return nil
}

// resumeDeletion は保存済みの認可結果と固定IDを使い、公開前に反映を照合する。
func (b *postingBoard) resumeDeletion(v DeletionRecord) (DeletionRecord, error) {
	defer b.pruneGuard()
	p := b.threads[uint64(v.Thread)]
	if p == nil {
		return v, app.ErrEvidenceGap
	}
	if v.Kind == "expire" {
		return b.resumeExpiry(v, p)
	}
	if v.Phase == "applied" || v.Phase == "cleaning" {
		if !p.ModerationApplied(v.TargetOperation, *v.TargetSeq, v.ID) {
			b.stopped = true
			return v, app.ErrEvidenceGap
		}
		if v.Kind == "hide" {
			p.BlockPublic(true)
		}
		return v, nil
	}
	p.BlockPublic(true)
	fail := func(e error) (DeletionRecord, error) { b.stopped = true; return v, e }
	if v.Phase == "intent" {
		v.Phase = "public_stopped"
		if e := b.saveDeletion(v); e != nil {
			return fail(e)
		}
		if e := b.afterDeletion("deletion:public_stopped"); e != nil {
			return fail(e)
		}
	}
	if v.Phase == "public_stopped" {
		if !p.ModerationApplied(v.TargetOperation, *v.TargetSeq, v.ID) {
			seq, _, e := p.ModerationState()
			if e != nil || seq != v.Expected {
				return fail(app.ErrEvidenceGap)
			}
			frame, e := p.PrepareModeration(v.input())
			if e != nil {
				return fail(e)
			}
			j, e := b.journal(time.Unix(0, int64(v.Created)))
			if e != nil {
				return fail(e)
			}
			if e = p.UseJournal(j); e != nil {
				return fail(e)
			}
			result := p.ApplyModeration(context.Background(), frame, domain.Time(b.clock().UnixNano()))
			if result.Status != store.Durable {
				return fail(errors.Join(app.ErrEvidenceGap, result.Err))
			}
		}
		if e := b.afterDeletion("deletion:thread"); e != nil {
			return fail(e)
		}
		v.Phase = "applied"
		if e := b.saveDeletion(v); e != nil {
			return fail(e)
		}
		if e := b.afterDeletion("deletion:applied"); e != nil {
			return fail(e)
		}
	}
	if !p.ModerationApplied(v.TargetOperation, *v.TargetSeq, v.ID) {
		return fail(app.ErrEvidenceGap)
	}
	if v.Kind == "redact" {
		p.BlockPublic(false)
	}
	return v, nil
}

func (b *postingBoard) loadDeletions() error {
	b.deletions = map[uint64]*store.ControlLog{}
	root := filepath.Join(b.root, "expiry", b.owner.String())
	if _, e := os.Lstat(root); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	keys, e := postingNames(root)
	if e != nil {
		return e
	}
	for _, key := range keys {
		dir := filepath.Join(root, fmt.Sprint(key))
		if _, e = inspectDeletionLayout(dir, b.owner, key); e != nil {
			return e
		}
		log, e := store.OpenControlWithValidators(dir, 3, b.owner, key, validateDeletion, snapshotDeletionValue)
		if e != nil {
			return e
		}
		b.deletions[key] = log
		if e = b.resumePendingCarrySnapshot(dir, key, log); e != nil {
			return e
		}
		b.deletionEpoch.Add(uint64(log.State().Seq))
		if e = validateDeletionTasks(log.State(), key); e != nil {
			return e
		}
		for name, row := range log.State().Rows {
			if strings.HasPrefix(name, "copy_task:") && !b.retentionEnabled {
				return store.ErrCorrupt
			}
			if !strings.HasPrefix(name, "deletion:") {
				continue
			}
			var v DeletionRecord
			if e = strictjson.Decode(row.Value, &v); e != nil {
				return e
			}
			if v.Board != b.owner || uint64(v.Thread) != key || v.Kind == "expire" && !b.retentionEnabled {
				return store.ErrCorrupt
			}
		}
	}
	return nil
}
func (b *postingBoard) recoverDeletions() error {
	records := []DeletionRecord{}
	known := map[domain.ID]uint64{}
	for _, log := range b.deletions {
		for name, row := range log.State().Rows {
			if !strings.HasPrefix(name, "deletion:") {
				continue
			}
			var v DeletionRecord
			if e := strictjson.Decode(row.Value, &v); e != nil {
				return e
			}
			if _, exists := known[v.TargetOperation]; exists {
				return app.ErrEvidenceGap
			}
			known[v.TargetOperation] = uint64(v.Thread)
			records = append(records, v)
		}
	}
	actions, e := b.threadActions()
	if e != nil {
		return e
	}
	for _, v := range actions {
		if _, exists := known[v.Operation]; exists {
			return app.ErrEvidenceGap
		}
		known[v.Operation] = uint64(v.Thread)
	}
	for key, p := range b.threads {
		for _, id := range p.AdministrativeOperationIDs() {
			if target, ok := known[id]; !ok || target != key {
				return app.ErrEvidenceGap
			}
		}
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Thread != records[j].Thread {
			return records[i].Thread < records[j].Thread
		}
		return records[i].Expected < records[j].Expected
	})
	// 先行intentを操作順に再開し、旧操作の照合と未確定操作の反映を混同しない。
	type recoveryStep struct {
		thread   domain.U64
		expected domain.U64
		deletion *DeletionRecord
		action   *ThreadActionRecord
	}
	steps := []recoveryStep{}
	for i := range records {
		v := &records[i]
		steps = append(steps, recoveryStep{v.Thread, v.Expected, v, nil})
	}
	for i := range actions {
		v := &actions[i]
		steps = append(steps, recoveryStep{v.Thread, v.Expected, nil, v})
	}
	sort.Slice(steps, func(i, j int) bool {
		if steps[i].thread != steps[j].thread {
			return steps[i].thread < steps[j].thread
		}
		return steps[i].expected < steps[j].expected
	})
	for _, step := range steps {
		var e error
		if step.action != nil {
			_, e = b.resumeThreadAction(*step.action)
		} else {
			_, e = b.resumeDeletion(*step.deletion)
		}
		if e != nil {
			return e
		}
	}
	// 古い削除行の反映で、後のexpire台帳の失効を解除しない。
	for _, v := range records {
		if v.Kind == "expire" {
			b.threads[uint64(v.Thread)].RestoreExpired()
		}
	}
	for key, log := range b.deletions {
		if e := verifyDeletionTasks(log.State(), b.threads[key]); e != nil {
			return e
		}
	}
	return nil
}

// inspectDeletionOwners は起動前に所有者・予約キー・最低reader版を照合する。
func inspectDeletionOwners(cfg Config, site siteState, boards []persistedBoard, allowPosting bool) error {
	owners, e := childIDs(filepath.Join(cfg.DataDir, "expiry"))
	if e != nil {
		return e
	}
	if len(owners) > 0 && (!allowPosting || site.MinimumReader < 14) {
		return errors.New("deletions require posting reader 14")
	}
	known := map[domain.ID]persistedBoard{}
	for _, b := range boards {
		known[b.info.ID] = b
	}
	for _, id := range owners {
		actionCount := 0
		b, ok := known[id]
		if !ok {
			return store.ErrCorrupt
		}
		var water struct {
			Last domain.U64 `json:"last_reserved_key"`
		}
		if e = strictjson.Decode(b.control.Rows["key_watermark:thread"].Value, &water); e != nil {
			return e
		}
		keys, e := postingNames(filepath.Join(cfg.DataDir, "expiry", id.String()))
		if e != nil {
			return e
		}
		for _, key := range keys {
			if key > uint64(water.Last) {
				return store.ErrCorrupt
			}
			dir := filepath.Join(cfg.DataDir, "expiry", id.String(), fmt.Sprint(key))
			m, e := inspectDeletionLayout(dir, id, key)
			if e != nil {
				return e
			}
			state, e := inspectDeletionControl(dir, id, key)
			if errors.Is(e, store.ErrIncomplete) {
				candidates, candidateErr := carrySnapshotCandidates(dir, m.Snapshot != nil)
				if candidateErr != nil {
					return candidateErr
				}
				if len(candidates) != 0 {
					return e
				}
				// 先行currentが保証する確定prefixを照合し、末尾の修復は所有者Openへ委ねる。
				m, checkErr := store.InspectControlManifest(dir)
				if checkErr != nil {
					return checkErr
				}
				if m.Kind != 3 || m.Owner != id || m.Subkey != domain.U64(key) {
					return store.ErrCorrupt
				}
				continue
			}
			if e != nil {
				return e
			}
			if e = checkDeletionSnapshotScope(site.MinimumReader, m, state); e != nil {
				return e
			}
			if e = validateDeletionTasks(state, key); e != nil {
				return e
			}
			if e = inspectCarryErasureReference(site.MinimumReader, b.control, state, id, key); e != nil {
				return e
			}
			candidates, e := carrySnapshotCandidates(dir, m.Snapshot != nil)
			if e != nil {
				return e
			}
			if len(candidates) != 0 {
				if e = checkCarrySnapshotState(site.MinimumReader, state); e != nil {
					return e
				}
			}
			for name := range state.Rows {
				if (name == "reclamation:audit" || name == "reclamation:audit_intent") && site.MinimumReader < 28 {
					return store.ErrCorrupt
				}
				if (strings.HasPrefix(name, "dedup_carry:") || strings.HasPrefix(name, "rate_carry:") || name == "reclamation:carry") && site.MinimumReader < 27 {
					return store.ErrCorrupt
				}
			}
			if _, ok := state.Rows["reclamation:body"]; ok {
				if site.MinimumReader < 26 {
					return store.ErrCorrupt
				}
				seed, err := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
				if err != nil {
					return err
				}
				public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
				clear(seed)
				if proof, err := readBodyReclamation(state, id, key, public); err != nil {
					return err
				} else if proof.Schema == 2 && site.MinimumReader < 27 {
					return store.ErrCorrupt
				}
				if err = inspectPendingCarrySnapshot(cfg, site.MinimumReader, dir, m, state, public); err != nil {
					return err
				}
			}
			threadActionCount := 0
			for name, row := range state.Rows {
				if strings.HasPrefix(name, "thread_action:") {
					actionCount++
					threadActionCount++
					if actionCount > 1024 || threadActionCount > 128 {
						return store.ErrCorrupt
					}
					var v ThreadActionRecord
					if strictjson.Decode(row.Value, &v) != nil || v.Board != id || uint64(v.Thread) != key || site.MinimumReader < 25 {
						return store.ErrCorrupt
					}
				}
				if !strings.HasPrefix(name, "deletion:") {
					continue
				}
				var v DeletionRecord
				if e = strictjson.Decode(row.Value, &v); e != nil {
					return e
				}
				if v.Board != id || uint64(v.Thread) != key || v.Kind == "expire" && site.MinimumReader < 16 {
					return store.ErrCorrupt
				}
			}
		}
	}
	return nil
}

func (b *postingBoard) afterDeletion(stage string) error {
	if b.deletionCheckpoint != nil {
		if e := b.deletionCheckpoint(stage); e != nil {
			return e
		}
	}
	b.checkpoint(stage)
	return nil
}
