// 隔離復元専用に、最新署名列で受理済みのframeを旧本文の末尾へ追いつかせる。
package app

import (
	"context"
	"errors"
	"sort"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// RestoreAcceptedPostingFrames は通常公開起動を遮断した作業先だけで呼ぶ。
// entriesは呼出元が最新列の署名・所有者・全連鎖を検証済みであること。未受理・署名原本回収済み・seq欠測を補わない。
func RestoreAcceptedPostingFrames(ctx context.Context, parent string, owner domain.ID, key uint64, entries []evidence.Entry) (err error) {
	p := &PostingLog{parent: parent, owner: owner, key: key, proposals: map[domain.ID]proposalEntry{}}
	decisions, e := p.loadEntries(entries)
	if e != nil {
		return e
	}
	p.thread, e = store.OpenThreadWithPack(parent, owner, key, func(s store.PackSnapshot) ([]store.ThreadRecord, error) {
		return p.verifyPack(s, func(id domain.ID) bool {
			d, ok := decisions[id]
			entry, found := p.proposals[id]
			return ok && found && d.Outcome == "accepted" && d.matches(entry.payload, entry.event)
		})
	})
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, p.Close()) }()
	pending, e := p.acceptedRestoreFrames(decisions)
	if e != nil {
		return e
	}
	for _, entry := range pending {
		if e = ctx.Err(); e != nil {
			return e
		}
		if entry.payload.ThreadSeq != p.thread.State().Revision+1 {
			return ErrEvidenceGap
		}
		frame, e := entry.decodeFrame()
		if e != nil {
			return e
		}
		result := p.thread.Append(frame)
		clear(frame)
		if result.Status != store.Durable {
			return errors.Join(ErrEvidenceGap, result.Err)
		}
	}
	return nil
}

// acceptedRestoreFrames は旧本文の操作照合後、最新列の受理済みでまだ未反映のframeだけを返す。
func (p *PostingLog) acceptedRestoreFrames(decisions map[domain.ID]postingDecision) ([]proposalEntry, error) {
	written := map[domain.ID]bool{}
	for _, record := range p.records() {
		entry, exists := p.proposals[record.ID]
		if !exists || entry.payload.FrameSHA != record.FrameSHA || entry.payload.ThreadSeq != record.Seq || entry.payload.Committed != record.Committed {
			return nil, ErrEvidenceGap
		}
		written[record.ID] = true
	}
	pending := []proposalEntry{}
	for id, decision := range decisions {
		entry, exists := p.proposals[id]
		if !exists || !decision.matches(entry.payload, entry.event) {
			return nil, ErrEvidenceGap
		}
		if decision.Outcome != "accepted" {
			if written[id] {
				return nil, ErrEvidenceGap
			}
			continue
		}
		if !written[id] {
			original, err := entry.originalPayload()
			if err != nil {
				return nil, err
			}
			if original.Frame == "" {
				return nil, ErrEvidenceGap
			}
			pending = append(pending, entry)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].payload.ThreadSeq < pending[j].payload.ThreadSeq })
	return pending, nil
}
