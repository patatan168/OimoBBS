// 投稿停止の容量床より前で、放置スレッドの公開本文と原本を有界に回収する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sort"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const storagePressureIdle = 7 * 24 * time.Hour

// StoragePressureStatus は管理用の容量回収結果。本文・接続情報は含めない。
type StoragePressureStatus struct {
	Enabled          bool   `json:"enabled"`
	Active           bool   `json:"active"`
	StopReason       string `json:"stop_reason"`
	RemovedOriginals uint64 `json:"removed_originals"`
	DroppedThreads   uint64 `json:"dropped_threads"`
	Checked          string `json:"checked"`
}

type pressureCandidate struct {
	worker          *postingBoard
	board           domain.ID
	key             uint64
	last            domain.Time
	full, reclaimed bool
}

// EnableStoragePressureReclamation は新しい削除writerより前にreader99をSyncする。
// 公開本文と満了原本の自動回収も有効にする。検査だけのOpenでは有効にしない。
func (r *Repository) EnableStoragePressureReclamation(ctx context.Context) error {
	if _, e := r.enableStorageReader(ctx, 99, "storage_pressure_enable"); e != nil {
		return e
	}
	if e := r.EnableRequiredOriginalReclamation(ctx); e != nil {
		return e
	}
	r.pressureEnabled.Store(true)
	return nil
}

// StoragePressure は直近の容量回収状態を管理認証内へ返す。
func (r *Repository) StoragePressure() StoragePressureStatus {
	if v := r.pressureStatus.Load(); v != nil {
		return *v
	}
	return StoragePressureStatus{Enabled: r.pressureEnabled.Load(), StopReason: "idle"}
}

// storagePressureNeeded は予約を除いた実空き容量に開始/終了の差を設ける。
// 投稿停止床+max(256MiB,床の10%)で開始し、その余裕の2倍まで回復したら止める。
func storagePressureNeeded(s PostingCapacityStatus, active bool) bool {
	if !s.Known {
		return false
	}
	margin := max(uint64(256<<20), s.FloorBytes/10)
	if active {
		margin *= 2
	}
	available := uint64(0)
	if s.AvailableBytes > s.ReservedBytes {
		available = s.AvailableBytes - s.ReservedBytes
	}
	return available < s.FloorBytes+margin+postingReservationBytes
}

// SweepStoragePressure は一回一スレッド・一日列128原本以内の回収を進める。
// 投稿workerが忙しい場合は延期し、容量不明・保全確認失敗では削除しない。
// 再起動後の進捗は署名済み回収記録から再構築し、HTTP投稿経路で全スレッドを走査しない。
func (r *Repository) SweepStoragePressure(ctx context.Context) (err error) {
	if !r.pressureEnabled.Load() || !r.pressureMu.TryLock() {
		return nil
	}
	defer r.pressureMu.Unlock()
	status := r.StoragePressure()
	status.Enabled = true
	defer func() {
		status.Checked = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			status.StopReason = "failed"
			if errors.Is(err, board.ErrBusy) {
				status.StopReason = "busy"
			}
		}
		r.pressureStatus.Store(&status)
	}()
	capacity := r.PostingCapacity()
	if !capacity.Known {
		status.StopReason = "capacity_unknown"
		return nil
	}
	if !storagePressureNeeded(capacity, status.Active) {
		status.Active = false
		status.StopReason = "enough_space"
		return nil
	}
	status.Active = true
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	now := time.Now()
	candidates, guard, e := r.prepareStoragePressure(ctx, now)
	if e != nil {
		return e
	}
	status.StopReason = "no_eligible_threads"
	for _, candidate := range candidates {
		b := candidate.worker
		value, e := b.worker.SubmitIdle(ctx, func() (any, error) {
			return r.reclaimPressureOwned(ctx, b, candidate, guard, domain.Time(now.UnixNano()))
		})
		if errors.Is(e, board.ErrBusy) {
			status.StopReason = "busy"
			continue
		}
		if e != nil {
			return e
		}
		result := value.(pressureResult)
		if result.held {
			status.StopReason = "protected"
			continue
		}
		status.DroppedThreads += result.dropped
		status.RemovedOriginals += uint64(result.removed)
		status.StopReason = "reclaiming"
		return nil
	}
	return nil
}

// prepareStoragePressure は候補と保全集合の確定中だけサイト排他を取る。
// 回収I/O中はサイト排他を解放し、他板の投稿・閲覧を待たせない。
func (r *Repository) prepareStoragePressure(ctx context.Context, now time.Time) ([]pressureCandidate, *disclosure.RequiredGCProtection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return nil, nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, nil, e
	}
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return nil, nil, e
	}
	if site.MinimumReader < 99 {
		return nil, nil, store.ErrIncomplete
	}
	guard, e := r.requiredReclaimProtection(ctx, site, now)
	if e != nil {
		return nil, nil, e
	}
	candidates, e := r.pressureCandidates(ctx, domain.Time(now.UnixNano()))
	return candidates, guard, e
}

// pressureCandidates は未満杯→満杯の順と最終投稿時刻で決定的に並べる。
// 既に公開回収済みで原本の残る列を先に完了させ、不要な追加スレ落としを避ける。
func (r *Repository) pressureCandidates(ctx context.Context, now domain.Time) ([]pressureCandidate, error) {
	out := []pressureCandidate{}
	for id, b := range r.posting {
		value, e := b.worker.SubmitIdle(ctx, func() (any, error) {
			rows := []pressureCandidate{}
			for key, p := range b.threads {
				last, full, pending, ok := p.StoragePressureState()
				if ok && last <= now-domain.Time(storagePressureIdle) && (!p.Reclaimed() || pending) {
					rows = append(rows, pressureCandidate{worker: b, board: id, key: key, last: last, full: full, reclaimed: p.Reclaimed()})
				}
			}
			return rows, nil
		})
		if errors.Is(e, board.ErrBusy) {
			continue
		}
		if e != nil {
			return nil, e
		}
		out = append(out, value.([]pressureCandidate)...)
	}
	sort.Slice(out, func(i, j int) bool { return pressureCandidateLess(out[i], out[j]) })
	return out, nil
}

func pressureCandidateLess(a, b pressureCandidate) bool {
	if a.reclaimed != b.reclaimed {
		return a.reclaimed
	}
	if a.full != b.full {
		return !a.full
	}
	if a.last != b.last {
		return a.last < b.last
	}
	if a.board != b.board {
		return a.board.String() < b.board.String()
	}
	return a.key < b.key
}

type pressureResult struct {
	held    bool
	dropped uint64
	removed int
}

func (r *Repository) reclaimPressureOwned(ctx context.Context, b *postingBoard, c pressureCandidate, guard *disclosure.RequiredGCProtection, now domain.Time) (pressureResult, error) {
	result := pressureResult{}
	p := b.threads[c.key]
	if b.stopped || p == nil || !b.bodyReclaimEnabled {
		return result, store.ErrIncomplete
	}
	last, _, _, ok := p.StoragePressureState()
	if !ok || last > now-domain.Time(storagePressureIdle) {
		return result, nil
	}
	held, e := p.StoragePressureHeld(requiredGCJournals(b), now, func(i evidence.RequiredPostingIdentity, at domain.Time) (bool, error) {
		return guard.PairHeld(b.owner, i, at)
	})
	if e != nil || held {
		result.held = held
		return result, e
	}
	if e = b.checkRequiredReclaimClock(now); e != nil {
		return result, e
	}
	if !p.Reclaimed() {
		// 走査後に容量が回復した場合は新しい公開停止を作らない。
		if !storagePressureNeeded(r.PostingCapacity(), true) {
			return result, nil
		}
		if e = b.savePressure(c.key, now); e != nil {
			return result, e
		}
		result.dropped = 1
		return result, nil
	}
	return r.prunePressureOriginals(ctx, b, c.key, guard, now, result)
}

// savePressure は通常期限を保った公開停止を先行Syncし、既存の回収手順へ渡す。
func (b *postingBoard) savePressure(key uint64, now domain.Time) error {
	p := b.threads[key]
	seq, expires, policy, ok := p.RetentionState()
	if !ok {
		return app.ErrEvidenceGap
	}
	var state boardValue
	if e := strictjson.Decode(b.control.State().Rows["board:state"].Value, &state); e != nil {
		return e
	}
	version := b.expirySiteVersion
	if b.currentSiteRevision != nil {
		version = b.currentSiteRevision()
	}
	v := DeletionRecord{ID: domain.NewID(), Board: b.owner, Thread: domain.U64(key), Kind: "pressure", Ranges: []app.RedactionRange{}, Expected: seq, TargetOperation: domain.NewID(), Format: 1, Phase: "intent", Created: now, Expires: expires, CleanupDue: now, Actor: domain.Actor{Kind: "system", Reason: "storage_pressure"}, Versions: domain.Versions{Site: version, Board: state.Settings.Version, Thread: policy}, Audit: "pending"}
	if e := b.saveDeletion(v); e != nil {
		b.stopped = true
		return e
	}
	if e := b.afterDeletion("pressure:intent"); e != nil {
		b.stopped = true
		return e
	}
	applied, e := b.resumeExpiry(v, p)
	if e != nil {
		return e
	}
	if e = b.reclaimPublicBody(applied); e != nil {
		b.stopped = true
		return e
	}
	proof, e := readBodyReclamation(b.deletions[key].State(), b.owner, key, b.key.Public().(ed25519.PublicKey))
	if e != nil || proof == nil {
		return errors.Join(store.ErrIncomplete, e)
	}
	return b.saveThreadAudit(*proof)
}

func (r *Repository) prunePressureOriginals(ctx context.Context, b *postingBoard, key uint64, guard *disclosure.RequiredGCProtection, now domain.Time, result pressureResult) (pressureResult, error) {
	proof, e := readBodyReclamation(b.deletions[key].State(), b.owner, key, b.key.Public().(ed25519.PublicKey))
	if e != nil || proof == nil {
		return result, errors.Join(store.ErrIncomplete, e)
	}
	if e = b.saveThreadAudit(*proof); e != nil {
		return result, e
	}
	cursor := r.pressureCursor
	if cursor.Board == nil || *cursor.Board != b.owner || uint64(cursor.Key) != key {
		id := b.owner
		cursor = requiredGCState{Board: &id, Key: domain.U64(key)}
	}
	cursor.At = now
	next, n, e := r.stepRequiredGCJobOwned(ctx, b, cursor, guard)
	if e == nil {
		if next.Advance {
			next.After = 0
			next.Day = 0
			next.Advance = false
		}
		r.pressureCursor = next
	}
	result.removed = n
	return result, e
}

// Description は管理画面へ直近の停止理由を日本語で表示する。
func (s StoragePressureStatus) Description() string {
	switch s.StopReason {
	case "failed":
		return "回収でエラー"
	case "capacity_unknown":
		return "容量を確認できないため待機"
	case "busy":
		return "投稿処理中のため延期"
	case "protected":
		return "候補が保全中のため待機"
	case "no_eligible_threads":
		return "回収できる古いスレッドなし"
	case "reclaiming":
		return "容量回収中"
	default:
		return "空き容量を監視中"
	}
}
