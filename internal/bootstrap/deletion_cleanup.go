// 最新削除版のpackを再証明し、公開系の旧base/delta回収をコピー別の台帳へ保存する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// DeletionCopyTask は本文なしのコピー別進捗。CopyIDは所有スレッドの固定識別子でpathではない。
type DeletionCopyTask struct {
	ID             domain.ID    `json:"id"`
	Deletion       domain.ID    `json:"deletion_id"`
	Kind           string       `json:"copy_kind"`
	CopyID         string       `json:"copy_id"`
	State          string       `json:"state"`
	ExpectedDigest domain.Hash  `json:"expected_digest"`
	Verified       *domain.Time `json:"verified_at_ns"`
	LastError      *string      `json:"last_error"`
}

// KindLabel は回収対象を管理画面へ表示し、公開本体と旧保存世代を区別する。
func (v DeletionCopyTask) KindLabel() string {
	if v.Kind == "live" {
		return "公開用保存データ"
	}
	return "旧WAL・pack"
}

// StateLabel はコピー別の状態を管理画面向けの固定文言に変換する。
func (v DeletionCopyTask) StateLabel() string {
	switch v.State {
	case "pending":
		return "待機中"
	case "running":
		return "掃除中"
	case "complete":
		return "回収済み"
	case "failed":
		return "再試行待ち"
	default:
		return "確認が必要"
	}
}

// ErrorLabel は内部パスを含めず延期理由を表示する。
func (v DeletionCopyTask) ErrorLabel() string {
	if v.LastError == nil {
		return ""
	}
	switch *v.LastError {
	case "capacity":
		return "空き容量不足"
	case "unavailable":
		return "公開停止・期限終了の本体回収待ち"
	default:
		return "保存状態の確認が必要"
	}
}

func validateDeletionCopyTask(key string, old, next json.RawMessage) error {
	var v DeletionCopyTask
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if v.ID == (domain.ID{}) || key != v.ID.String() || v.Deletion == (domain.ID{}) || (v.Kind != "base_delta" && v.Kind != "live") || !strings.HasPrefix(v.CopyID, "thread:") || v.ExpectedDigest == (domain.Hash{}) {
		return store.ErrCorrupt
	}
	if v.State != "pending" && v.State != "running" && v.State != "complete" && v.State != "failed" {
		return store.ErrCorrupt
	}
	if (v.State == "complete") != (v.Verified != nil) || v.Verified != nil && *v.Verified <= 0 || (v.State == "failed") != (v.LastError != nil) {
		return store.ErrCorrupt
	}
	if v.LastError != nil && *v.LastError != "capacity" && *v.LastError != "storage" && *v.LastError != "unavailable" {
		return store.ErrCorrupt
	}
	if len(old) == 0 {
		if v.State != "pending" {
			return store.ErrCorrupt
		}
		return nil
	}
	var prior DeletionCopyTask
	if e := strictjson.Decode(old, &prior); e != nil {
		return e
	}
	if !((prior.State == "pending" || prior.State == "failed") && v.State == "running" || prior.State == "running" && (v.State == "complete" || v.State == "failed")) {
		return store.ErrCorrupt
	}
	prior.State, prior.Verified, prior.LastError = v.State, v.Verified, v.LastError
	if !reflect.DeepEqual(prior, v) {
		return store.ErrCorrupt
	}
	return nil
}

// validateDeletionTasks は同じkind3内の削除ID・copy識別・一意性を起動前に照合する。
func validateDeletionTasks(state store.ControlState, key uint64) error {
	seen := map[domain.ID]bool{}
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "copy_task:") {
			continue
		}
		var v DeletionCopyTask
		if e := strictjson.Decode(row.Value, &v); e != nil {
			return e
		}
		var deletion DeletionRecord
		if e := strictjson.Decode(state.Rows["deletion:"+v.Deletion.String()].Value, &deletion); e != nil {
			return e
		}
		if seen[v.Deletion] || (v.Kind == "base_delta" && deletion.Kind != "redact") || (v.Kind == "live" && deletion.Kind != "hide" && deletion.Kind != "expire" && deletion.Kind != "pressure") || v.CopyID != fmt.Sprintf("thread:%d", key) || deletion.Thread != domain.U64(key) || (deletion.Phase != "applied" && deletion.Phase != "cleaning") {
			return store.ErrCorrupt
		}
		seen[v.Deletion] = true
	}
	return nil
}

// verifyDeletionTasks はコピー別進捗を署名済み操作と現行保存世代へ照合する。
func verifyDeletionTasks(state store.ControlState, p *app.PostingLog) error {
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "copy_task:") {
			continue
		}
		var task DeletionCopyTask
		if e := strictjson.Decode(row.Value, &task); e != nil {
			return e
		}
		var v DeletionRecord
		if e := strictjson.Decode(state.Rows["deletion:"+task.Deletion.String()].Value, &v); e != nil {
			return e
		}
		if task.Kind == "live" {
			if e := verifyBodyTask(state, task, p); e != nil {
				return e
			}
			continue
		}
		if p == nil || v.TargetSeq == nil {
			return app.ErrEvidenceGap
		}
		digest, ok := p.AdministrativeDigest(v.TargetOperation)
		if !ok || digest != task.ExpectedDigest {
			return app.ErrEvidenceGap
		}
		if task.State == "complete" {
			if e := p.RedactionStorageClean(*v.TargetSeq); e != nil {
				return e
			}
		}
	}
	return nil
}

func (b *postingBoard) saveDeletionTask(key uint64, v DeletionCopyTask) error {
	log := b.deletions[key]
	if log == nil {
		return app.ErrEvidenceGap
	}
	b.deletionEpoch.Add(1)
	frame, e := controlFrame(log.State(), domain.NewID(), domain.Time(b.clock().UnixNano()), "thread_cleanup", []store.Mutation{mutation("copy_task", v.ID.String(), v, nil)}, []string{v.Deletion.String()})
	if e == nil {
		result := log.Append(frame)
		if result.Status != store.Durable {
			e = errors.Join(ErrPostingUnavailable, result.Err)
		}
	}
	if e != nil {
		b.stopped = true
	}
	return e
}

// cleanRedactions は一回につき最大limit操作を処理する。監査/backupの未完了は残す。
// 容量不足はコピーのfailedとして記録し、公開反映済みを掃除完了へ読み替えない。
func (b *postingBoard) cleanRedactions(limit int) error {
	if limit < 1 || limit > 64 {
		return errors.New("cleanup limit must be 1..64")
	}
	if b.stopped {
		return ErrPostingUnavailable
	}
	keys := make([]uint64, 0, len(b.deletions))
	for key := range b.deletions {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	processed := 0
	for _, key := range keys {
		state := b.deletions[key].State()
		tasks := map[domain.ID]DeletionCopyTask{}
		deletions := []DeletionRecord{}
		for name, row := range state.Rows {
			if strings.HasPrefix(name, "copy_task:") {
				var v DeletionCopyTask
				if e := strictjson.Decode(row.Value, &v); e != nil {
					return e
				}
				tasks[v.Deletion] = v
			} else if strings.HasPrefix(name, "deletion:") {
				var v DeletionRecord
				if e := strictjson.Decode(row.Value, &v); e != nil {
					return e
				}
				if v.Kind == "redact" && (v.Phase == "applied" || v.Phase == "cleaning") {
					deletions = append(deletions, v)
				}
			}
		}
		sort.Slice(deletions, func(i, j int) bool { return deletions[i].Expected < deletions[j].Expected })
		for _, v := range deletions {
			if tasks[v.ID].State == "complete" {
				continue
			}
			cursor := fmt.Sprintf("%020d/%020d", key, v.Expected)
			if cursor <= b.redactionCleanupAfter {
				continue
			}
			if processed == limit {
				return nil
			}
			b.redactionCleanupAfter = cursor
			processed++
			if e := b.cleanRedaction(key, v, tasks[v.ID]); e != nil {
				return e
			}
		}
	}
	b.redactionCleanupAfter = ""
	return nil
}

func (b *postingBoard) cleanRedaction(key uint64, v DeletionRecord, task DeletionCopyTask) error {
	p := b.threads[key]
	if p == nil || v.TargetSeq == nil || !p.ModerationApplied(v.TargetOperation, *v.TargetSeq, v.ID) {
		b.stopped = true
		return app.ErrEvidenceGap
	}
	digest, ok := p.AdministrativeDigest(v.TargetOperation)
	if !ok || task.ID != (domain.ID{}) && task.ExpectedDigest != digest {
		b.stopped = true
		return app.ErrEvidenceGap
	}
	if task.ID == (domain.ID{}) {
		task = DeletionCopyTask{ID: domain.NewID(), Deletion: v.ID, Kind: "base_delta", CopyID: fmt.Sprintf("thread:%d", key), State: "pending", ExpectedDigest: digest}
		if e := b.saveDeletionTask(key, task); e != nil {
			return e
		}
		if e := b.afterDeletion("cleanup:task_pending"); e != nil {
			b.stopped = true
			return e
		}
	}
	if v.Phase == "applied" {
		v.Phase = "cleaning"
		if e := b.saveDeletion(v); e != nil {
			b.stopped = true
			return e
		}
		if e := b.afterDeletion("cleanup:cleaning"); e != nil {
			b.stopped = true
			return e
		}
	}
	if task.State != "running" {
		task.State, task.LastError = "running", nil
		if e := b.saveDeletionTask(key, task); e != nil {
			return e
		}
		if e := b.afterDeletion("cleanup:task_running"); e != nil {
			b.stopped = true
			return e
		}
	}
	if p.Reclaimed() {
		if e := p.RedactionStorageClean(*v.TargetSeq); e != nil {
			b.stopped = true
			return e
		}
		return b.completeDeletionTask(key, task, "cleanup:copy_complete")
	}
	fail := func(code string, e error) error {
		task.State, task.LastError = "failed", &code
		if saveErr := b.saveDeletionTask(key, task); saveErr != nil {
			return errors.Join(e, saveErr)
		}
		if p.StorageStopped() {
			b.stopped = true
			return e
		}
		return nil
	}
	if p.PublicExpired(domain.Time(b.clock().UnixNano())) {
		return fail("unavailable", ErrPostingUnavailable)
	}
	if b.reserveDeletionPack != nil {
		release, e := b.reserveDeletionPack()
		if e != nil {
			return fail("capacity", e)
		}
		defer release()
	}
	if _, e := p.CompactWithClock(context.Background(), b.clock, 6, true); e != nil {
		return fail("storage", e)
	}
	if e := b.afterDeletion("cleanup:pack"); e != nil {
		b.stopped = true
		return e
	}
	if _, e := p.ReclaimPack(context.Background(), domain.Time(b.clock().UnixNano()), true); e != nil {
		return fail("storage", e)
	}
	if e := b.afterDeletion("cleanup:old_files"); e != nil {
		b.stopped = true
		return e
	}
	return b.completeDeletionTask(key, task, "cleanup:copy_complete")
}

func (b *postingBoard) completeDeletionTask(key uint64, task DeletionCopyTask, stage string) error {
	now := domain.Time(b.clock().UnixNano())
	task.State, task.Verified, task.LastError = "complete", &now, nil
	if e := b.saveDeletionTask(key, task); e != nil {
		return e
	}
	if e := b.afterDeletion(stage); e != nil {
		b.stopped = true
		return e
	}
	return nil
}
