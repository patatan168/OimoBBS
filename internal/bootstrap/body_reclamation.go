// 公開本体の回収を先行署名・コピー進捗・所有列内の再開へ接続する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func validateBodyReclamation(key string, old, next json.RawMessage) error {
	var v app.BodyReclamation
	if key != "body" || len(old) != 0 || strictjson.Decode(next, &v) != nil || v.Schema != 2 || v.Deletion == (domain.ID{}) || v.Owner == (domain.ID{}) || v.Key == 0 || v.Sequence == 0 || v.Sequence > store.MaxPackEntries || v.At <= 0 || v.Floor < 0 || v.Expires <= 0 || v.Policy.Validate() != nil || v.RecordsSHA == (domain.Hash{}) || v.DedupSHA == (domain.Hash{}) || v.RateSHA == (domain.Hash{}) || store.ValidateBodySourceFiles(v.Files) != nil {
		return store.ErrCorrupt
	}
	if v.Kind == "hide" {
		if v.After.State != "hidden" {
			return store.ErrCorrupt
		}
	} else if v.Kind != "expire" || v.At < v.Expires {
		return store.ErrCorrupt
	}
	signature, e := base64.RawStdEncoding.Strict().DecodeString(v.Signature)
	if e != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != v.Signature {
		return store.ErrCorrupt
	}
	return nil
}

func reclamationDigest(v app.BodyReclamation) domain.Hash {
	raw, _ := json.Marshal(v)
	return sha256.Sum256(raw)
}

// readBodyReclamation は署名・削除正本・所有位置を照合し、未署名の本体欠落を許さない。
func readBodyReclamation(state store.ControlState, owner domain.ID, key uint64, public ed25519.PublicKey) (*app.BodyReclamation, error) {
	row, ok := state.Rows["reclamation:body"]
	if !ok {
		return nil, nil
	}
	var v app.BodyReclamation
	if e := strictjson.Decode(row.Value, &v); e != nil {
		return nil, e
	}
	if v.Owner != owner || uint64(v.Key) != key || v.Verify(public) != nil {
		return nil, store.ErrCorrupt
	}
	var deletion DeletionRecord
	if strictjson.Decode(state.Rows["deletion:"+v.Deletion.String()].Value, &deletion) != nil || deletion.Board != owner || uint64(deletion.Thread) != key || deletion.Kind != v.Kind || deletion.Expires != v.Expires || deletion.Created > v.At || deletion.Phase != "applied" && deletion.Phase != "cleaning" {
		return nil, store.ErrCorrupt
	}
	seq := deletion.Expected
	if deletion.TargetSeq != nil {
		seq = *deletion.TargetSeq
	}
	if v.Sequence != seq {
		return nil, store.ErrCorrupt
	}
	task, e := bodyTask(state, v.Deletion)
	if e != nil || task.ID == (domain.ID{}) || task.ExpectedDigest != reclamationDigest(v) {
		return nil, errors.Join(store.ErrCorrupt, e)
	}
	var intent *threadAuditTransfer
	if row, ok := state.Rows["reclamation:audit_intent"]; ok {
		var audit threadAuditTransfer
		if strictjson.Decode(row.Value, &audit) != nil || audit.verify(v, public) != nil {
			return nil, store.ErrCorrupt
		}
		intent = &audit
	}
	if row, ok := state.Rows["reclamation:audit"]; ok {
		var audit threadAuditTransfer
		if intent == nil || strictjson.Decode(row.Value, &audit) != nil || !reflect.DeepEqual(audit, *intent) || deletion.Audit != "complete" {
			return nil, store.ErrCorrupt
		}
	} else if deletion.Audit == "complete" {
		return nil, store.ErrCorrupt
	}
	carry, e := readBodyCarry(state, v)
	if e != nil {
		return nil, e
	}
	if v.Schema == 2 && task.State == "complete" && carry == nil {
		return nil, store.ErrCorrupt
	}
	if carry != nil && carry.Retirement != nil {
		if e := verifyErasedCarryBody(carry, v, task, public); e != nil {
			return nil, e
		}
	}
	return &v, nil
}

// verifyErasedCarryBody は元正本の署名コピーを検証し、未完了bodyの行削除を拒否する。
func verifyErasedCarryBody(carry *app.BodyCarry, proof app.BodyReclamation, task DeletionCopyTask, public ed25519.PublicKey) error {
	if task.State != "complete" {
		return store.ErrCorrupt
	}
	return carry.Retirement.Verify(proof, domain.Time(time.Now().UnixNano()), public)
}

func bodyTask(state store.ControlState, deletion domain.ID) (DeletionCopyTask, error) {
	var out DeletionCopyTask
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "copy_task:") {
			continue
		}
		var v DeletionCopyTask
		if e := strictjson.Decode(row.Value, &v); e != nil {
			return out, e
		}
		if v.Kind == "live" && v.Deletion == deletion {
			if out.ID != (domain.ID{}) {
				return out, store.ErrCorrupt
			}
			out = v
		}
	}
	return out, nil
}

func (b *postingBoard) bodyReclamations() (map[uint64]app.BodyReclamation, error) {
	out := map[uint64]app.BodyReclamation{}
	var water struct {
		Last domain.U64 `json:"last_removed_bump"`
	}
	if e := strictjson.Decode(b.control.State().Rows["bump_watermark:ranking"].Value, &water); e != nil {
		return nil, e
	}
	public := b.key.Public().(ed25519.PublicKey)
	for key, log := range b.deletions {
		v, e := readBodyReclamation(log.State(), b.owner, key, public)
		if e != nil {
			return nil, e
		}
		if v != nil {
			if v.After.BumpValue > water.Last {
				return nil, store.ErrCorrupt
			}
			out[key] = *v
		}
	}
	return out, nil
}

func verifyBodyTask(state store.ControlState, task DeletionCopyTask, p *app.PostingLog) error {
	var v app.BodyReclamation
	if strictjson.Decode(state.Rows["reclamation:body"].Value, &v) != nil || task.Deletion != v.Deletion || task.ExpectedDigest != reclamationDigest(v) || p == nil || !p.Reclaimed() {
		return app.ErrEvidenceGap
	}
	seq, expires, _, ok := p.RetentionState()
	if !ok || seq != v.Sequence || expires != v.Expires {
		return app.ErrEvidenceGap
	}
	return nil
}

// EnablePublicBodyReclamation はreader27を先行Syncし、公開本体を毎分有界回収する。
// 非公開証拠・媒体・既存backupの回収や全体completeを表す機能ではない。
func (r *Repository) EnablePublicBodyReclamation(ctx context.Context) error {
	if _, e := r.enableStorageReader(ctx, 27, "thread_body_reclaim_enable"); e != nil {
		return e
	}
	if e := r.EnableThreadRetention(ctx); e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.posting {
		if _, e := b.worker.Submit(ctx, func() (any, error) {
			b.bodyReclaimEnabled = true
			b.carryEnabled = true
			if e := b.resumePublicBodies(); e != nil {
				b.stopped = true
				return nil, e
			}
			return nil, b.cleanPublicBodies(8)
		}); e != nil {
			return e
		}
	}
	return nil
}

// ReclaimPublicBodies は期限失効済み・hide確定済みの公開本体だけを有界回収する。
func (r *Repository) ReclaimPublicBodies(ctx context.Context, limit int) error {
	if limit < 1 || limit > 64 {
		return errors.New("cleanup limit must be 1..64")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	for _, b := range r.posting {
		if _, e := b.worker.Submit(ctx, func() (any, error) {
			if !b.bodyReclaimEnabled {
				return nil, errors.New("enable public body reclamation first")
			}
			if _, e := b.scanExpiry(true); e != nil {
				return nil, e
			}
			return nil, b.cleanPublicBodies(limit)
		}); e != nil {
			return e
		}
	}
	return nil
}

func (b *postingBoard) cleanPublicBodies(limit int) error {
	if !b.bodyReclaimEnabled {
		return nil
	}
	if b.stopped {
		return ErrPostingUnavailable
	}
	records := []DeletionRecord{}
	for _, log := range b.deletions {
		for name, row := range log.State().Rows {
			if !strings.HasPrefix(name, "deletion:") {
				continue
			}
			var v DeletionRecord
			if e := strictjson.Decode(row.Value, &v); e != nil {
				return e
			}
			if v.Kind != "hide" && v.Kind != "expire" || v.Phase != "applied" && v.Phase != "cleaning" {
				continue
			}
			if p := b.threads[uint64(v.Thread)]; p != nil && !p.Reclaimed() {
				records = append(records, v)
			}
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CleanupDue != records[j].CleanupDue {
			return records[i].CleanupDue < records[j].CleanupDue
		}
		return records[i].Thread < records[j].Thread
	})
	for _, v := range records[:min(limit, len(records))] {
		if p := b.threads[uint64(v.Thread)]; p.Reclaimed() {
			continue
		}
		if e := b.reclaimPublicBody(v); e != nil {
			b.stopped = true
			return e
		}
	}
	return nil
}

func (b *postingBoard) reclaimPublicBody(v DeletionRecord) error {
	p := b.threads[uint64(v.Thread)]
	if p == nil {
		return app.ErrEvidenceGap
	}
	if v.Kind == "hide" && (v.TargetSeq == nil || !p.ModerationApplied(v.TargetOperation, *v.TargetSeq, v.ID)) {
		return app.ErrEvidenceGap
	}
	seq, expires, _, ok := p.RetentionState()
	if !ok || expires != v.Expires || (v.Kind == "expire" && seq != v.Expected) {
		return app.ErrEvidenceGap
	}
	proof, e := p.PrepareBodyReclamation(context.Background(), v.ID, v.Kind, max(domain.Time(b.clock().UnixNano()), v.Created), b.key)
	if e != nil {
		return e
	}
	var water struct {
		Last domain.U64 `json:"last_removed_bump"`
	}
	if e = strictjson.Decode(b.control.State().Rows["bump_watermark:ranking"].Value, &water); e != nil {
		return e
	}
	if water.Last < proof.After.BumpValue {
		water.Last = proof.After.BumpValue
		if e = appendControl(b.control, "thread_body_watermark", []store.Mutation{mutation("bump_watermark", "ranking", water, nil)}, []string{fmt.Sprint(v.Thread)}); e != nil {
			return e
		}
	}
	if e = b.afterDeletion("reclaim:watermark"); e != nil {
		return e
	}
	task := DeletionCopyTask{ID: domain.NewID(), Deletion: v.ID, Kind: "live", CopyID: fmt.Sprintf("thread:%d", v.Thread), State: "pending", ExpectedDigest: reclamationDigest(proof)}
	log := b.deletions[uint64(v.Thread)]
	frame, e := controlFrame(log.State(), domain.NewID(), domain.Time(b.clock().UnixNano()), "thread_body_reclamation", []store.Mutation{mutation("reclamation", "body", proof, nil), mutation("copy_task", task.ID.String(), task, nil)}, []string{v.ID.String()})
	if e != nil {
		return e
	}
	b.deletionEpoch.Add(1)
	result := log.Append(frame)
	if result.Status != store.Durable {
		p.BlockPublic(true)
		return errors.Join(ErrPostingUnavailable, result.Err)
	}
	if e = b.afterDeletion("reclaim:proof"); e != nil {
		return e
	}
	if e = p.RetireBody(proof); e != nil {
		return e
	}
	return b.finishPublicBody(proof)
}

func (b *postingBoard) finishPublicBody(proof app.BodyReclamation) error {
	key := uint64(proof.Key)
	if b.carryEnabled {
		if e := b.saveBodyCarry(proof); e != nil {
			return e
		}
		carry, e := b.boundBodyCarry(b.deletions[key].State(), proof)
		if e != nil || carry == nil {
			return errors.Join(store.ErrCorrupt, e)
		}
		if e = b.threads[key].RestoreBodyCarry(*carry, domain.Time(b.clock().UnixNano()), b.key.Public().(ed25519.PublicKey)); e != nil {
			return e
		}
	}
	state := b.deletions[key].State()
	task, e := bodyTask(state, proof.Deletion)
	if e != nil || task.ID == (domain.ID{}) {
		return errors.Join(app.ErrEvidenceGap, e)
	}
	if row, ok := state.Rows["reclamation:audit"]; ok {
		var audit threadAuditTransfer
		if strictjson.Decode(row.Value, &audit) != nil {
			return store.ErrCorrupt
		}
		if e = b.verifyThreadAuditDays(audit); e != nil {
			return e
		}
	}
	dir := filepath.Join(b.threadsDir, fmt.Sprint(key))
	if task.State == "complete" {
		if _, e = os.Lstat(dir); !os.IsNotExist(e) {
			return errors.Join(store.ErrCorrupt, e)
		}
		return store.SyncDirectory(b.threadsDir)
	}
	var v DeletionRecord
	if e = strictjson.Decode(state.Rows["deletion:"+proof.Deletion.String()].Value, &v); e != nil {
		return e
	}
	if v.Phase == "applied" {
		v.Phase = "cleaning"
		if e = b.saveDeletion(v); e != nil {
			return e
		}
	}
	if e = b.afterDeletion("reclaim:cleaning"); e != nil {
		return e
	}
	if task.State != "running" {
		task.State, task.LastError = "running", nil
		if e = b.saveDeletionTask(key, task); e != nil {
			return e
		}
	}
	if e = b.afterDeletion("reclaim:running"); e != nil {
		return e
	}
	if e = store.RemoveReclaimedBody(context.Background(), dir, proof.Files, b.afterDeletion); e != nil {
		code := "storage"
		task.State, task.LastError = "failed", &code
		return errors.Join(e, b.saveDeletionTask(key, task))
	}
	at := max(domain.Time(b.clock().UnixNano()), proof.At)
	task.State, task.Verified, task.LastError = "complete", &at, nil
	if e = b.saveDeletionTask(key, task); e != nil {
		return e
	}
	return b.afterDeletion("reclaim:complete")
}

// resumePublicBodies は受理記録・削除正本の照合が済んだ後、公開受付より先に掃除を再開する。
func (b *postingBoard) resumePublicBodies() error {
	proofs, e := b.bodyReclamations()
	if e != nil {
		return e
	}
	for key, v := range proofs {
		p := b.threads[key]
		if p == nil || !p.Reclaimed() {
			return app.ErrEvidenceGap
		}
		if _, ok := b.deletions[key].State().Rows["reclamation:audit_intent"]; ok {
			if e = b.saveThreadAudit(v); e != nil {
				return e
			}
		}
		if e = b.finishPublicBody(v); e != nil {
			return e
		}
	}
	return nil
}
