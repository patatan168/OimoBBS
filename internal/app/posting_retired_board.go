// 必須原本の削除証跡も板全体で一度だけ分類し、予約高水位と本文なし復旧へ渡す。
package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"slices"
)

type postingEvidenceGroups struct {
	retiredFloor domain.Time
	entries      map[uint64][]evidence.Entry
	retired      map[uint64]map[domain.ID]retiredPostingOriginals
	ids          map[domain.ID]bool
	operations   map[domain.ID]uint64
}

// checkJournalPostingKeys は原本文を複製せず、元行と削除証跡のキーだけを予約高水位へ照合する。
func checkJournalPostingKeys(j *evidence.Journal, watermark uint64) error {
	retired, e := j.RequiredRetirements()
	if e != nil {
		return e
	}
	for _, r := range retired {
		if r.Identity.ThreadKey == 0 || uint64(r.Identity.ThreadKey) > watermark {
			return fmt.Errorf("evidence thread key exceeds reservation watermark")
		}
	}
	return j.Visit(func(entry evidence.Entry) error {
		if entry.Event.Kind == "journal_checkpoint" {
			return nil
		}
		if entry.Event.Kind == "tombstone" {
			var marker struct {
				Reason string `json:"reason"`
			}
			if json.Unmarshal(entry.Payload, &marker) != nil || !evidence.RequiredRetirementReason(marker.Reason) {
				return ErrEvidenceGap
			}
			return nil
		}
		var link struct {
			Key domain.U64 `json:"thread_key"`
		}
		if json.Unmarshal(entry.Payload, &link) != nil || link.Key == 0 || uint64(link.Key) > watermark {
			return fmt.Errorf("evidence thread key exceeds reservation watermark")
		}
		return nil
	})
}

// groupPostingEvidence は全期間の元/削除イベントIDと操作の所属キーを一回の分類で照合する。
func groupPostingEvidence(owner domain.ID, journals []*evidence.Journal, active *evidence.Journal) (*postingEvidenceGroups, error) {
	g := &postingEvidenceGroups{entries: map[uint64][]evidence.Entry{}, retired: map[uint64]map[domain.ID]retiredPostingOriginals{}, ids: map[domain.ID]bool{}, operations: map[domain.ID]uint64{}}
	seen := map[*evidence.Journal]bool{}
	for _, j := range journals {
		if j == nil || j.Owner() != owner || seen[j] {
			return nil, ErrEvidenceGap
		}
		seen[j] = true
		if e := g.addJournal(j); e != nil {
			return nil, e
		}
	}
	if active != nil && !seen[active] {
		return nil, ErrEvidenceGap
	}
	return g, nil
}

// addJournal は元行と固定型の削除証跡を区別し、両方を重複/所属検査へ含める。
func (g *postingEvidenceGroups) addJournal(j *evidence.Journal) error {
	floor, e := j.RequiredRetirementFloor()
	if e != nil {
		return e
	}
	if floor > g.retiredFloor {
		g.retiredFloor = floor
	}
	for _, entry := range j.Entries() {
		if e := g.addCurrentEntry(entry); e != nil {
			return e
		}
	}
	retired, e := j.RequiredRetirements()
	if e != nil {
		return e
	}
	for _, r := range retired {
		if e = g.addRetirement(r); e != nil {
			return e
		}
	}
	return nil
}

// addCurrentEntry は現在行のIDと所属を固定し、回収証跡の本文を通常投稿へ読み替えない。
func (g *postingEvidenceGroups) addCurrentEntry(entry evidence.Entry) error {
	if g.ids[entry.Event.RecordID] {
		return ErrEvidenceGap
	}
	g.ids[entry.Event.RecordID] = true
	if entry.Event.Kind == "journal_checkpoint" {
		return nil
	}
	if entry.Event.Kind == "tombstone" {
		var marker struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(entry.Payload, &marker) != nil || !evidence.RequiredRetirementReason(marker.Reason) {
			return ErrEvidenceGap
		}
		return nil
	}
	var link struct {
		Key domain.U64 `json:"thread_key"`
		ID  domain.ID  `json:"operation_id"`
	}
	if json.Unmarshal(entry.Payload, &link) != nil {
		return ErrEvidenceGap
	}
	if e := g.bindOperation(uint64(link.Key), link.ID); e != nil {
		return e
	}
	g.entries[uint64(link.Key)] = append(g.entries[uint64(link.Key)], entry)
	return nil
}

// bindOperation は操作IDが別キーへ移された記録を拒否する。
func (g *postingEvidenceGroups) bindOperation(key uint64, id domain.ID) error {
	if key == 0 || id == (domain.ID{}) {
		return ErrEvidenceGap
	}
	if old, found := g.operations[id]; found && old != key {
		return ErrEvidenceGap
	}
	g.operations[id] = key
	return nil
}

// addRetirement は元IDの二重使用と、一操作の回収済み両側の対応不一致を拒否する。
func (g *postingEvidenceGroups) addRetirement(r evidence.RequiredRetirement) error {
	if g.ids[r.Envelope.RecordID] {
		return ErrEvidenceGap
	}
	g.ids[r.Envelope.RecordID] = true
	key := uint64(r.Identity.ThreadKey)
	if r.Envelope.Kind == rejectedConnectionKind {
		return g.bindOperation(key, r.Identity.OperationID)
	}
	if e := g.bindOperation(key, r.Identity.OperationID); e != nil {
		return e
	}
	if g.retired[key] == nil {
		g.retired[key] = map[domain.ID]retiredPostingOriginals{}
	}
	p := &PostingLog{retired: g.retired[key]}
	if e := p.addRetiredOriginal(r); e != nil {
		return e
	}
	if _, exists := g.entries[key]; !exists {
		g.entries[key] = nil
	}
	return nil
}

// OpenPostingsWithRetiredOriginals は原本の残るキーと回収済みキーを板全体で復旧する。
// 全期間を一度だけ分類し、回収済み受理原本には署名済み公開回収証明とcarryを必須とする。
// 未受理原本だけの回収では公開WALを照合して通常threadを維持する。
// 全キーが成功するまで結果を返さず、失敗時は開いたwriterを閉じる。製品有効化は別途行う。
func OpenPostingsWithRetiredOriginals(parent string, owner domain.ID, keys []uint64, journals []*evidence.Journal, active *evidence.Journal, now domain.Time, proofs map[uint64]BodyReclamation, carries map[uint64]BodyCarry, public ed25519.PublicKey) (map[uint64]*PostingLog, error) {
	if e := checkExpiredBoardCarries(owner, proofs, carries, now, public); e != nil {
		return nil, e
	}
	if owner == (domain.ID{}) || active == nil || active.Owner() != owner {
		return nil, ErrEvidenceGap
	}
	g, e := groupPostingEvidence(owner, journals, active)
	if e != nil {
		return nil, e
	}
	if now < g.retiredFloor {
		return nil, fmt.Errorf("%w: %w", ErrEvidenceGap, evidence.ErrRetirementClock)
	}
	if e = g.includePostingKeys(keys, proofs, carries); e != nil {
		return nil, e
	}
	return g.openPostings(parent, owner, active, now, proofs, carries, public)
}

// includePostingKeys は実キー/回収証明の和集合を固定し、証明のないcarryを拒否する。
func (g *postingEvidenceGroups) includePostingKeys(keys []uint64, proofs map[uint64]BodyReclamation, carries map[uint64]BodyCarry) error {
	for _, key := range keys {
		if key == 0 {
			return ErrEvidenceGap
		}
		if _, exists := g.entries[key]; !exists {
			g.entries[key] = nil
		}
	}
	for key := range proofs {
		if key == 0 {
			return ErrEvidenceGap
		}
		if _, exists := g.entries[key]; !exists {
			g.entries[key] = nil
		}
	}
	for key := range carries {
		if _, exists := proofs[key]; !exists {
			return ErrEvidenceGap
		}
	}
	return nil
}

// openPostings は固定分類済みキーを順に開き、途中失敗のwriterを残さない。
func (g *postingEvidenceGroups) openPostings(parent string, owner domain.ID, active *evidence.Journal, now domain.Time, proofs map[uint64]BodyReclamation, carries map[uint64]BodyCarry, public ed25519.PublicKey) (map[uint64]*PostingLog, error) {
	keys := make([]uint64, 0, len(g.entries))
	for key := range g.entries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := map[uint64]*PostingLog{}
	for _, key := range keys {
		p := &PostingLog{parent: parent, owner: owner, key: key, active: active, proposals: map[domain.ID]proposalEntry{}, retired: g.retired[key], retiredFloor: g.retiredFloor}
		e := p.openGroupedEvidence(g.entries[key], now, proofs, carries, public)
		if e != nil {
			_ = p.Close()
			for _, opened := range result {
				_ = opened.Close()
			}
			return nil, e
		}
		result[key] = p
	}
	return result, nil
}

// openGroupedEvidence は原本の有無に応じて完全frameか本文なし回収証明の経路を選ぶ。
func (p *PostingLog) openGroupedEvidence(entries []evidence.Entry, now domain.Time, proofs map[uint64]BodyReclamation, carries map[uint64]BodyCarry, public ed25519.PublicKey) error {
	decisions, e := p.loadEntries(entries)
	if e != nil {
		return e
	}
	proof, hasProof := proofs[p.key]
	carry, hasCarry := carries[p.key]
	if p.hasAcceptedRetirement() {
		if !hasProof || !hasCarry {
			return ErrEvidenceGap
		}
		e = p.openGroupedRetirement(proof, &carry, decisions, now, public)
	} else if hasProof {
		e = p.openGroupedReclaimed(proof, carry, hasCarry, decisions, now, public)
	} else {
		return p.openThread(decisions, now)
	}
	if e != nil {
		return e
	}
	return store.CheckReclaimedBody(context.Background(), filepath.Join(p.parent, fmt.Sprint(p.key)), proof.Files)
}

// openGroupedReclaimed は満了証跡の時計を修復より先に検査してから元証拠を復旧する。
func (p *PostingLog) openGroupedReclaimed(proof BodyReclamation, carry BodyCarry, hasCarry bool, decisions map[domain.ID]postingDecision, now domain.Time, public ed25519.PublicKey) error {
	if hasCarry && carry.Retirement != nil {
		if e := carry.verifyRetirement(proof, now, public); e != nil {
			return e
		}
	}
	if e := p.openReclaimed(proof, decisions, public); e != nil {
		return e
	}
	if hasCarry {
		return p.RestoreBodyCarry(carry, now, public)
	}
	return nil
}

// openGroupedRetirement は原本回収の期限境界を確認して本文なし復旧へ渡す。
func (p *PostingLog) openGroupedRetirement(proof BodyReclamation, carry *BodyCarry, decisions map[domain.ID]postingDecision, now domain.Time, public ed25519.PublicKey) error {
	for _, v := range p.retired {
		if !retirementTimeValid(v, proof, now) {
			return ErrEvidenceGap
		}
	}
	return p.openRetiredReclamation(proof, carry, decisions, now, public)
}

// hasAcceptedRetirement は公開回収証明が必要な受理原本の回収有無を返す。
func (p *PostingLog) hasAcceptedRetirement() bool {
	for _, r := range p.retired {
		if r.identity.Outcome == "accepted" {
			return true
		}
	}
	return false
}
