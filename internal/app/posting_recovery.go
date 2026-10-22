// 投稿と署名記録を全件照合し、確定記録の欠落だけを元の操作のまま補完する。
package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"sort"
)

// ErrEvidenceGap は投稿正本と必須記録を照合できず公開を拒否したことを表す。
var ErrEvidenceGap = errors.New("evidence_gap")

// OpenPosting は予約済みキーを開く。journalsには当該板の全期間の記録を渡す。
// 通常投稿のproposalだけならnot_accepted、完全なthreadありならacceptedを同期保存する。
// 未反映の管理proposalは先行intentの所有者が同じ固定操作で再開し、公開前に台帳を照合する。
// 未決定createの完全WALだけは署名済み要求と照合してcurrentを補完する。
// それ以外のcurrent欠落・未完了ディレクトリは公開しない。
func OpenPosting(parent string, owner domain.ID, key uint64, journals []*evidence.Journal, active *evidence.Journal, now domain.Time) (*PostingLog, error) {
	return OpenPostingWithReclamation(parent, owner, key, journals, active, now, nil, nil)
}

// OpenPostingWithReclamation は単一キーの署名済み回収正本を、受理記録と残存ファイルへ照合する。
func OpenPostingWithReclamation(parent string, owner domain.ID, key uint64, journals []*evidence.Journal, active *evidence.Journal, now domain.Time, proof *BodyReclamation, public ed25519.PublicKey) (*PostingLog, error) {
	if owner == (domain.ID{}) || key == 0 || active == nil || active.Owner() != owner {
		return nil, errors.New("invalid posting owner")
	}
	p := &PostingLog{parent: parent, owner: owner, key: key, active: active, proposals: map[domain.ID]proposalEntry{}}
	decisions, e := p.loadEvidence(journals)
	if e != nil {
		return nil, e
	}
	if now < p.retiredFloor {
		return nil, evidence.ErrRetirementClock
	}
	if proof != nil {
		e = p.openReclaimed(*proof, decisions, public)
		if e == nil {
			e = store.CheckReclaimedBody(context.Background(), filepath.Join(parent, fmt.Sprint(key)), proof.Files)
		}
	} else {
		e = p.openThread(decisions, now)
	}
	if e != nil {
		return nil, e
	}
	return p, nil
}

func (p *PostingLog) openThread(decisions map[domain.ID]postingDecision, now domain.Time) error {
	var e error
	path := filepath.Join(p.parent, fmt.Sprint(p.key))
	if _, e = os.Lstat(path); e == nil {
		if _, err := os.Lstat(filepath.Join(path, "current.json")); os.IsNotExist(err) {
			if e = p.recoverCreation(decisions); e != nil {
				return fmt.Errorf("%w: thread creation recovery: %w", ErrEvidenceGap, e)
			}
		}
		p.thread, e = store.OpenThreadWithPack(p.parent, p.owner, p.key, func(s store.PackSnapshot) ([]store.ThreadRecord, error) {
			return p.verifyPack(s, func(id domain.ID) bool {
				d, ok := decisions[id]
				entry, found := p.proposals[id]
				return ok && found && d.Outcome == "accepted" && d.matches(entry.payload, entry.event)
			})
		})
		if e != nil {
			return fmt.Errorf("%w: thread recovery: %w", ErrEvidenceGap, e)
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if e = p.reconcile(decisions, now); e != nil {
		_ = p.Close()
		return e
	}
	if p.thread != nil && now >= p.thread.State().Expires {
		p.expired = true
	} else {
		p.publish()
	}
	return nil
}

// recoverCreation は未決定の単一createだけを初回WAL補完へ渡す。
// 既存の決定や複数操作があれば、参照喪失を作成途中と推測しない。
func (p *PostingLog) recoverCreation(decisions map[domain.ID]postingDecision) error {
	if len(decisions) != 0 || len(p.proposals) != 1 || len(p.retired) != 0 {
		return ErrEvidenceGap
	}
	for _, entry := range p.proposals {
		if entry.event.Kind != "evidence_proposal" || entry.payload.ThreadSeq != 1 {
			return ErrEvidenceGap
		}
		frame, err := entry.decodeFrame()
		if err != nil {
			return err
		}
		return store.RecoverThreadCreation(p.parent, p.owner, p.key, frame)
	}
	return ErrEvidenceGap
}

func (p *PostingLog) loadEvidence(journals []*evidence.Journal) (map[domain.ID]postingDecision, error) {
	entries, e := p.loadRetiredJournals(journals)
	if e != nil {
		return nil, e
	}
	if p.hasAcceptedRetirement() {
		return nil, ErrEvidenceGap
	}

	return p.loadEntries(entries)
}

func (p *PostingLog) loadEntries(entries []evidence.Entry) (map[domain.ID]postingDecision, error) {
	decisions := map[domain.ID]postingDecision{}
	decisionKinds := map[domain.ID]string{}
	var decisionEvents map[domain.ID]evidence.Event
	if len(p.retired) != 0 {
		decisionEvents = map[domain.ID]evidence.Event{}
	}
	for _, entry := range entries {
		switch entry.Event.Kind {
		case rejectedConnectionKind, "journal_checkpoint":
			continue
		case "evidence_proposal", "thread_admin_proposal":
			var proposal postingProposal
			if e := strictjson.Decode(entry.Payload, &proposal); e != nil {
				return nil, e
			}
			if proposal.ThreadKey != domain.U64(p.key) {
				continue
			}
			if _, exists := p.proposals[proposal.OperationID]; exists {
				return nil, fmt.Errorf("%w: duplicate proposal", ErrEvidenceGap)
			}
			p.proposals[proposal.OperationID] = retainProposalEntry(proposal, entry.Event)
		case "evidence_decision", "thread_admin_decision":
			var decision postingDecision
			if e := strictjson.Decode(entry.Payload, &decision); e != nil {
				return nil, e
			}
			if decision.ThreadKey != domain.U64(p.key) {
				continue
			}
			if _, exists := decisions[decision.OperationID]; exists {
				return nil, fmt.Errorf("%w: duplicate decision", ErrEvidenceGap)
			}
			decisions[decision.OperationID] = decision
			decisionKinds[decision.OperationID] = entry.Event.Kind
			if decisionEvents != nil {
				decisionEvents[decision.OperationID] = entry.Event
			}
		default:
			return nil, errors.New("unsupported posting evidence")
		}
	}
	if e := p.restoreRetiredEntries(decisions, decisionKinds, decisionEvents); e != nil {
		return nil, e
	}
	if e := p.checkRejectedConnections(entries, decisions); e != nil {
		return nil, e
	}
	for id, kind := range decisionKinds {
		proposal, exists := p.proposals[id]
		if !exists || (kind == "thread_admin_decision") != (proposal.event.Kind == "thread_admin_proposal") {
			return nil, fmt.Errorf("%w: decision kind differs from proposal", ErrEvidenceGap)
		}
	}
	return decisions, nil
}

func (p *PostingLog) reconcile(decisions map[domain.ID]postingDecision, now domain.Time) error {
	records := map[domain.ID]store.ThreadRecord{}
	if p.thread != nil || p.reclaimed != nil {
		for _, record := range p.records() {
			if _, exists := records[record.ID]; exists {
				return fmt.Errorf("%w: repeated WAL operation ID", ErrEvidenceGap)
			}
			records[record.ID] = record
			entry, exists := p.proposals[record.ID]
			if !exists || entry.payload.FrameSHA != record.FrameSHA || entry.payload.ThreadSeq != record.Seq || entry.payload.Committed != record.Committed {
				return fmt.Errorf("%w: WAL without matching proposal", ErrEvidenceGap)
			}
		}
	}
	for id, decision := range decisions {
		entry, exists := p.proposals[id]
		if !exists || !decision.matches(entry.payload, entry.event) {
			return fmt.Errorf("%w: decision without matching proposal", ErrEvidenceGap)
		}
		_, written := records[id]
		if (decision.Outcome == "accepted") != written {
			return fmt.Errorf("%w: decision differs from WAL", ErrEvidenceGap)
		}
	}
	// 全照合が済むまで、復旧による記録追加も公開も行わない。
	pending := make([]proposalEntry, 0)
	for id, entry := range p.proposals {
		if _, done := decisions[id]; !done {
			if entry.event.Kind == "thread_admin_proposal" {
				if _, written := records[id]; !written {
					continue // 先行削除intentの所有者が同じ固定操作で再開する。
				}
			}
			pending = append(pending, entry)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].payload.ThreadSeq != pending[j].payload.ThreadSeq {
			return pending[i].payload.ThreadSeq < pending[j].payload.ThreadSeq
		}
		return pending[i].event.RecordID.String() < pending[j].event.RecordID.String()
	})
	for _, entry := range pending {
		outcome := "not_accepted"
		if _, written := records[entry.payload.OperationID]; written {
			outcome = "accepted"
		}
		if r := p.decide(entry, outcome, true, now); r.Status != store.Durable {
			return fmt.Errorf("recovery decision not durable: %w", r.Err)
		}
	}
	return nil
}
