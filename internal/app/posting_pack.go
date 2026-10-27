// 圧縮packを署名済み受理操作から再証明し、公開内容を変えず保存先を切り替える。
package app

import (
	"bytes"
	"context"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"sort"
	"time"
)

// verifyPack は署名journalに含まれる受理済みframeだけを順に再生する。
// pack側で再送・監査が満了していても、元の受理操作と現在値の照合を省略しない。
func (p *PostingLog) verifyPack(s store.PackSnapshot, accepted func(domain.ID) bool) ([]store.ThreadRecord, error) {
	if s.Owner != p.owner || s.Key != p.key {
		return nil, ErrEvidenceGap
	}
	entries := []proposalEntry{}
	for id, entry := range p.proposals {
		if entry.payload.ThreadSeq <= s.State.Revision && accepted(id) {
			entries = append(entries, entry)
		}
	}
	if uint64(len(entries)) != uint64(s.State.Revision) || len(entries) > store.MaxPackEntries {
		return nil, ErrEvidenceGap
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].payload.ThreadSeq < entries[j].payload.ThreadSeq })
	builder := store.NewPackBuilder(nil)
	for _, entry := range entries {
		raw, e := entry.decodeFrame()
		if e != nil {
			return nil, e
		}
		f, n, e := store.ReadFrame(bytes.NewReader(raw))
		if e != nil || n != int64(len(raw)) {
			return nil, ErrEvidenceGap
		}
		if e = builder.Apply(f); e != nil {
			return nil, e
		}
	}
	expected, e := store.EncodePack(builder.Snapshot(s.Owner, s.Key, s.Generation, s.At), 0)
	if e != nil {
		return nil, e
	}
	actual, e := store.EncodePack(s, 0)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(actual, expected) {
		return nil, ErrEvidenceGap
	}
	return builder.Records(), nil
}

// PostingPackReport は非公開本文を含まない圧縮候補・適用結果。
type PostingPackReport struct {
	Generation uint64     `json:"storage_generation"`
	Sequence   domain.U64 `json:"sequence"`
	Bytes      int        `json:"pack_bytes"`
	Applied    bool       `json:"applied"`
}

// Compact は所有ワーカー専用。apply=falseなら生成・証明のみ行い保存先を変更しない。
// 初版は停止中CLIから利用し、旧WAL・旧pack・署名journalを残す。
func (p *PostingLog) Compact(ctx context.Context, now domain.Time, level uint8, apply bool) (PostingPackReport, error) {
	return p.CompactWithClock(ctx, func() time.Time { return time.Unix(0, int64(now)) }, level, apply)
}

// CompactWithClock は保存処理中にも所有ワーカーの時計で期限を再確認する。
func (p *PostingLog) CompactWithClock(ctx context.Context, clock func() time.Time, level uint8, apply bool) (PostingPackReport, error) {
	if clock == nil {
		return PostingPackReport{}, errors.New("clock required")
	}
	now := domain.Time(clock().UnixNano())
	fail := func(e error) (PostingPackReport, error) { return PostingPackReport{}, e }
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	if p.stopped || p.thread == nil || p.PublicExpired(now) {
		return fail(errors.New("thread unavailable for compaction"))
	}
	raw, e := p.thread.PreparePack(now, level)
	if e != nil {
		return fail(e)
	}
	s, e := store.DecodePack(raw)
	if e != nil {
		return fail(e)
	}
	accepted := map[domain.ID]bool{}
	for _, r := range p.thread.Records() {
		accepted[r.ID] = true
	}
	if _, e = p.verifyPack(s, func(id domain.ID) bool { return accepted[id] }); e != nil {
		return fail(e)
	}
	report := PostingPackReport{Generation: s.Generation, Sequence: s.State.Revision, Bytes: len(raw)}
	if !apply {
		return report, nil
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	result := p.thread.SwitchPackGuarded(raw, func() error {
		if p.PublicExpired(domain.Time(clock().UnixNano())) {
			return errors.New("thread expired during compaction")
		}
		return nil
	})
	if result.Status != store.Durable {
		if result.Status == store.Unknown {
			p.stopWriter()
			p.snapshot = nil
		}
		return fail(result.Err)
	}
	report.Applied = true
	return report, nil
}

// ReclaimPack は現行packと受理証拠を再照合してから、未参照の旧保存世代を回収する。
// 証拠journal・バックアップ・currentより新しい中断候補は対象にしない。
func (p *PostingLog) ReclaimPack(ctx context.Context, now domain.Time, apply bool) (store.ThreadReclaimReport, error) {
	if _, e := p.Compact(ctx, now, 6, false); e != nil {
		return store.ThreadReclaimReport{}, e
	}
	if e := ctx.Err(); e != nil {
		return store.ThreadReclaimReport{}, e
	}
	report, e := p.thread.ReclaimOldFiles(apply)
	if e != nil && p.thread.StorageStopped() {
		p.stopWriter()
		p.snapshot = nil
	}
	return report, e
}

// StorageStopped は所有ワーカーが板全体の停止へ伝播させる保存停止状態を返す。
func (p *PostingLog) StorageStopped() bool { return p.stopped }

// RedactionStorageClean は削除位置以降の現行packと保存世代の構造を再確認する。
// 後日の正常な圧縮で生じた旧削除版も許し、完了記録の位置矛盾を拒否する。
func (p *PostingLog) RedactionStorageClean(revision domain.U64) error {
	if p.reclaimed != nil && p.reclaimed.proof.Sequence >= revision {
		return nil
	}
	if p.thread == nil || p.thread.PackedSequence() < revision {
		return ErrEvidenceGap
	}
	_, e := p.thread.ReclaimOldFiles(false)
	if e != nil {
		return e
	}
	return nil
}
