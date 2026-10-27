// 回収済みスレッドの操作監査を、先行署名・日別receipt・削除正本の順で引き渡す。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type threadAuditDay struct {
	Day   string      `json:"utc_day"`
	Count uint32      `json:"entry_count"`
	SHA   domain.Hash `json:"summary_sha256"`
}
type threadAuditTransfer struct {
	Schema    uint32           `json:"schema"`
	Board     domain.ID        `json:"board_id"`
	Thread    domain.U64       `json:"thread_key"`
	Deletion  domain.ID        `json:"deletion_id"`
	Proof     domain.Hash      `json:"reclamation_sha256"`
	Sequence  domain.U64       `json:"source_seq"`
	Since     domain.Time      `json:"required_since_ns"`
	Created   domain.Time      `json:"created_at_ns"`
	Days      []threadAuditDay `json:"days"`
	Signature string           `json:"signature"`
}

func (v threadAuditTransfer) shape() error {
	if v.Schema != 1 || v.Board == (domain.ID{}) || v.Thread == 0 || v.Deletion == (domain.ID{}) || v.Proof == (domain.Hash{}) || v.Sequence == 0 || v.Sequence > store.MaxPackEntries || v.Created <= domain.Time(auditRetention) || v.Since != v.Created-domain.Time(auditRetention) || v.Days == nil || len(v.Days) > 182 {
		return store.ErrCorrupt
	}
	prior := ""
	total := uint64(0)
	for _, day := range v.Days {
		at, e := time.Parse("20060102", day.Day)
		if e != nil || at.UTC().Format("20060102") != day.Day || day.Day <= prior || day.Count == 0 || day.SHA == (domain.Hash{}) || at.UnixNano() > int64(v.Created) || at.AddDate(0, 0, 1).UnixNano() <= int64(v.Since) {
			return store.ErrCorrupt
		}
		prior = day.Day
		total += uint64(day.Count)
	}
	if total > uint64(v.Sequence) {
		return store.ErrCorrupt
	}
	raw, e := base64.RawStdEncoding.Strict().DecodeString(v.Signature)
	if e != nil || len(raw) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(raw) != v.Signature {
		return store.ErrCorrupt
	}
	return nil
}

func (v threadAuditTransfer) verify(proof app.BodyReclamation, key ed25519.PublicKey) error {
	if v.shape() != nil || v.Board != proof.Owner || v.Thread != proof.Key || v.Deletion != proof.Deletion || v.Proof != reclamationDigest(proof) || v.Sequence != proof.Sequence || len(key) != ed25519.PublicKeySize {
		return store.ErrCorrupt
	}
	signature, _ := base64.RawStdEncoding.DecodeString(v.Signature)
	v.Signature = ""
	raw, _ := json.Marshal(v)
	if !ed25519.Verify(key, append([]byte("oimo/thread-audit-transfer/v1\x00"), raw...), signature) {
		return store.ErrCorrupt
	}
	return nil
}

func validateThreadAuditTransfer(key string, old, next json.RawMessage) error {
	if len(old) != 0 || (key != "audit_intent" && key != "audit") {
		return store.ErrCorrupt
	}
	var v threadAuditTransfer
	if strictjson.Decode(next, &v) != nil {
		return store.ErrCorrupt
	}
	return v.shape()
}

func threadAuditRows(board domain.ID, key domain.U64, rows []store.PackAudit) map[string][]threadAuditStored {
	out := map[string][]threadAuditStored{}
	for _, a := range rows {
		day := time.Unix(0, int64(a.Committed)).UTC().Format("20060102")
		out[day] = append(out[day], threadAuditStored{a.ID, "thread_summary", board, key, a.Committed, a.Expires, a})
	}
	return out
}

func threadAuditDigest(rows []threadAuditStored) domain.Hash {
	h := sha256.New()
	for _, v := range rows {
		raw, _ := json.Marshal(v)
		h.Write(raw)
		h.Write([]byte{'\n'})
	}
	var out domain.Hash
	copy(out[:], h.Sum(nil))
	return out
}

func (b *postingBoard) makeThreadAuditTransfer(proof app.BodyReclamation) (threadAuditTransfer, error) {
	now := domain.Time(b.clock().UnixNano())
	v := threadAuditTransfer{Schema: 1, Board: b.owner, Thread: proof.Key, Deletion: proof.Deletion, Proof: reclamationDigest(proof), Sequence: proof.Sequence, Created: now, Since: now - domain.Time(auditRetention), Days: []threadAuditDay{}}
	rows, e := b.threads[uint64(proof.Key)].ThreadAudit(v.Since)
	if e != nil {
		return v, e
	}
	groups := threadAuditRows(b.owner, proof.Key, rows)
	for day, rows := range groups {
		v.Days = append(v.Days, threadAuditDay{day, uint32(len(rows)), threadAuditDigest(rows)})
	}
	sort.Slice(v.Days, func(i, j int) bool { return v.Days[i].Day < v.Days[j].Day })
	raw, _ := json.Marshal(v)
	v.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(b.key, append([]byte("oimo/thread-audit-transfer/v1\x00"), raw...)))
	return v, v.verify(proof, b.key.Public().(ed25519.PublicKey))
}

func (b *postingBoard) saveThreadAudit(proof app.BodyReclamation) (err error) {
	log := b.deletions[uint64(proof.Key)]
	state := log.State()
	var transfer threadAuditTransfer
	if row, ok := state.Rows["reclamation:audit"]; ok {
		if strictjson.Decode(row.Value, &transfer) != nil || transfer.verify(proof, b.key.Public().(ed25519.PublicKey)) != nil {
			return store.ErrCorrupt
		}
		return b.verifyThreadAuditDays(transfer)
	}
	if row, ok := state.Rows["reclamation:audit_intent"]; ok {
		if strictjson.Decode(row.Value, &transfer) != nil || transfer.verify(proof, b.key.Public().(ed25519.PublicKey)) != nil {
			return store.ErrCorrupt
		}
	} else {
		transfer, err = b.makeThreadAuditTransfer(proof)
		if err != nil {
			return err
		}
		b.deletionEpoch.Add(1)
		if err = appendControl(log, "thread_audit_intent", []store.Mutation{mutation("reclamation", "audit_intent", transfer, nil)}, []string{proof.Deletion.String()}); err != nil {
			return err
		}
	}
	if err = b.afterDeletion("audit:intent"); err != nil {
		return err
	}
	rows, err := b.threads[uint64(proof.Key)].ThreadAudit(transfer.Since)
	if err != nil {
		return err
	}
	groups := threadAuditRows(b.owner, proof.Key, rows)
	if len(groups) != len(transfer.Days) {
		return app.ErrEvidenceGap
	}
	sink := auditSink{root: filepath.Join(b.root, "audit"), remember: b.rememberAudit}
	defer func() { err = errors.Join(err, sink.close()) }()
	for _, day := range transfer.Days {
		values := groups[day.Day]
		if len(values) != int(day.Count) || threadAuditDigest(values) != day.SHA {
			return app.ErrEvidenceGap
		}
		if err = sink.open(b.owner, "board", day.Day); err != nil {
			return err
		}
		if err = b.importThreadAuditRows(sink.log, values); err != nil {
			return err
		}
		key := fmt.Sprintf("thread:%d:%s", proof.Key, proof.Deletion)
		state := sink.log.State()
		raw, _ := json.Marshal(transfer)
		if prior, ok := state.Rows["import_receipt:"+key]; ok {
			if !bytes.Equal(prior.Value, raw) {
				return store.ErrCorrupt
			}
		} else if err = appendControl(sink.log, "thread_audit_receipt", []store.Mutation{mutation("import_receipt", key, transfer, nil)}, []string{proof.Deletion.String()}); err != nil {
			return err
		}
		if err = b.afterDeletion("audit:receipt"); err != nil {
			return err
		}
	}
	if err = sink.close(); err != nil {
		return err
	}
	if err = b.verifyThreadAuditDays(transfer); err != nil {
		return err
	}
	state = log.State()
	var deletion DeletionRecord
	if strictjson.Decode(state.Rows["deletion:"+proof.Deletion.String()].Value, &deletion) != nil {
		return store.ErrCorrupt
	}
	deletion.Audit = "complete"
	change := mutation("deletion", deletion.ID.String(), deletion, nil)
	change.ExpectedRevision = state.Rows["deletion:"+deletion.ID.String()].Revision
	b.deletionEpoch.Add(1)
	if err = appendControl(log, "thread_audit_complete", []store.Mutation{mutation("reclamation", "audit", transfer, nil), change}, []string{deletion.ID.String()}); err != nil {
		return err
	}
	return b.afterDeletion("audit:ledger")
}

// verifyThreadAuditDays は未満了の日別要約とreceiptを固定署名の集合へ照合する。
func (b *postingBoard) verifyThreadAuditDays(v threadAuditTransfer) error {
	if b.auditRefs == nil {
		b.auditRefs = map[string]store.ControlBackupReference{}
	}
	now := b.clock()
	for _, day := range v.Days {
		at, _ := time.Parse("20060102", day.Day)
		if !now.Before(at.AddDate(0, 0, 1).Add(auditRetention)) {
			continue
		}
		path := filepath.Join(b.root, "audit", b.owner.String(), day.Day)
		subkey := uint64(at.Year()*10000 + int(at.Month())*100 + at.Day())
		log, e := store.OpenControl(path, 4, b.owner, subkey, auditValueValidator(b.owner, "board", day.Day))
		if e != nil {
			return e
		}
		state := log.State()
		rows := []threadAuditStored{}
		for name, row := range state.Rows {
			if !strings.HasPrefix(name, "audit_entry:") || !isThreadAudit(row.Value) {
				continue
			}
			var entry threadAuditStored
			if strictjson.Decode(row.Value, &entry) != nil {
				return errors.Join(store.ErrCorrupt, log.Close())
			}
			if entry.Thread == v.Thread && entry.At > v.Since && entry.Payload.Seq <= v.Sequence {
				rows = append(rows, entry)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Payload.Seq < rows[j].Payload.Seq })
		raw, _ := json.Marshal(v)
		receipt := state.Rows[fmt.Sprintf("import_receipt:thread:%d:%s", v.Thread, v.Deletion)]
		if len(rows) != int(day.Count) || threadAuditDigest(rows) != day.SHA || !bytes.Equal(receipt.Value, raw) {
			return errors.Join(store.ErrCorrupt, log.Close())
		}
		ref, e := log.BackupReference(domain.Time(at.AddDate(0, 0, 1).Add(auditRetention).UnixNano()))
		if e = errors.Join(e, log.Close()); e != nil {
			return e
		}
		b.auditRefs[day.Day] = ref
	}
	return nil
}

// TransferThreadAudits は板所有列で回収済み監査を一回最大limit件ずつ引き渡す。
func (r *Repository) TransferThreadAudits(ctx context.Context, limit int) error {
	return r.transferThreadAudits(ctx, limit, false)
}

// transferThreadAudits は周期保守だけ実行中の板を延期し、明示実行の待機契約は保つ。
func (r *Repository) transferThreadAudits(ctx context.Context, limit int, idle bool) error {
	if limit < 1 || limit > 64 {
		return errors.New("audit transfer limit must be 1..64")
	}
	// 周期経路はreader28を確認済み。形式有効化の全板監査を毎回やり直さない。
	if !idle {
		if _, e := r.enableStorageReader(ctx, 28, "thread_audit_transfer_enable"); e != nil {
			return e
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	for _, b := range r.posting {
		submit := b.worker.Submit
		if idle {
			submit = b.worker.SubmitIdle
		}
		if _, e := submit(ctx, func() (any, error) {
			if b.stopped {
				return nil, ErrPostingUnavailable
			}
			proofs, e := b.bodyReclamations()
			if e != nil {
				return nil, e
			}
			keys := []uint64{}
			for key := range proofs {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			count := 0
			for _, key := range keys {
				if _, ok := b.deletions[key].State().Rows["reclamation:audit"]; ok {
					continue
				}
				if count >= limit {
					break
				}
				if e = b.saveThreadAudit(proofs[key]); e != nil {
					b.stopped = true
					return nil, e
				}
				count++
			}
			return nil, nil
		}); e != nil {
			if idle && errors.Is(e, board.ErrBusy) {
				continue
			}
			return e
		}
	}
	return nil
}

// maintainThreadAudits はreader28以降で管理者のある運用だけ、同じ保守周期で引渡しを継続する。
// 非必須ログ等のreader更新だけで、管理者のない検証環境に監査移管を新設しない。
func (r *Repository) maintainThreadAudits(ctx context.Context) error {
	r.mu.Lock()
	var site siteState
	err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site)
	var accounts []administrator
	if err == nil {
		accounts, err = r.administrators()
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if site.MinimumReader < 28 || len(accounts) == 0 {
		return nil
	}
	return r.transferThreadAudits(ctx, 8, true)
}

// importThreadAuditRows は署名に固定された要約を有界frameにまとめ、各Sync後にだけ進む。
func (b *postingBoard) importThreadAuditRows(log *store.ControlLog, values []threadAuditStored) error {
	state := log.State()
	changes := []store.Mutation{}
	size := 0
	flush := func() error {
		if len(changes) == 0 {
			return nil
		}
		if e := appendControl(log, "thread_audit_import", changes, []string{}); e != nil {
			return e
		}
		changes = []store.Mutation{}
		size = 0
		return b.afterDeletion("audit:entry")
	}
	for _, v := range values {
		raw, _ := json.Marshal(v)
		if prior, ok := state.Rows["audit_entry:"+v.ID.String()]; ok {
			if !bytes.Equal(prior.Value, raw) || prior.Expires == nil || *prior.Expires != v.Expires {
				return store.ErrCorrupt
			}
			continue
		}
		change := mutation("audit_entry", v.ID.String(), v, &v.Expires)
		encoded, _ := json.Marshal(change)
		if len(encoded) > store.MaxOperationJSON-4096 {
			return store.ErrCorrupt
		}
		if len(changes) == 128 || size+len(encoded)+1 > store.MaxOperationJSON-4096 {
			if e := flush(); e != nil {
				return e
			}
		}
		changes = append(changes, change)
		size += len(encoded) + 1
	}
	return flush()
}
