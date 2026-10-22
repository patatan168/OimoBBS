// 板全体の記録を一度だけ分類し、再送索引とスレッド復旧へ渡す。
package app

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"slices"
)

// OpenPostings は実ディレクトリと記録が参照するキーの和集合を復旧する。
// 成功するまでmapを公開しない。journalsの全期間列挙と排他は呼出元の責務。
func OpenPostings(parent string, owner domain.ID, keys []uint64, journals []*evidence.Journal, active *evidence.Journal, now domain.Time) (map[uint64]*PostingLog, error) {
	return OpenPostingsWithReclamations(parent, owner, keys, journals, active, now, nil, nil)
}

// OpenPostingsWithReclamations は先行署名を持つ回収済みキーだけ、公開本体なしの復旧を許す。
func OpenPostingsWithReclamations(parent string, owner domain.ID, keys []uint64, journals []*evidence.Journal, active *evidence.Journal, now domain.Time, reclaimed map[uint64]BodyReclamation, public ed25519.PublicKey) (map[uint64]*PostingLog, error) {
	if owner == (domain.ID{}) || active == nil || active.Owner() != owner {
		return nil, errors.New("invalid board posting owner")
	}
	groups := map[uint64][]evidence.Entry{}
	for key := range reclaimed {
		groups[key] = nil
	}
	for _, key := range keys {
		if key == 0 {
			return nil, errors.New("zero thread key")
		}
		groups[key] = nil
	}
	seen := map[*evidence.Journal]bool{}
	eventIDs := map[domain.ID]bool{}
	operations := map[domain.ID]uint64{}
	for _, j := range journals {
		if j == nil || j.Owner() != owner || seen[j] {
			return nil, errors.New("invalid board journals")
		}
		seen[j] = true
		for _, entry := range j.Entries() {
			if entry.Event.Kind == "journal_checkpoint" {
				continue
			}
			var link struct {
				Key domain.U64 `json:"thread_key"`
				ID  domain.ID  `json:"operation_id"`
			}
			if e := json.Unmarshal(entry.Payload, &link); e != nil || link.Key == 0 || link.ID == (domain.ID{}) {
				return nil, ErrEvidenceGap
			}
			key := uint64(link.Key)
			if eventIDs[entry.Event.RecordID] {
				return nil, ErrEvidenceGap
			}
			eventIDs[entry.Event.RecordID] = true
			if old, ok := operations[link.ID]; ok && old != key {
				return nil, ErrEvidenceGap
			}
			operations[link.ID] = key
			groups[key] = append(groups[key], entry)
		}
	}
	if !seen[active] {
		return nil, errors.New("active journal absent")
	}
	ordered := make([]uint64, 0, len(groups))
	for key := range groups {
		ordered = append(ordered, key)
	}
	slices.Sort(ordered)
	out := map[uint64]*PostingLog{}
	for _, key := range ordered {
		p := &PostingLog{parent: parent, owner: owner, key: key, active: active, proposals: map[domain.ID]proposalEntry{}}
		decisions, e := p.loadEntries(groups[key])
		if e == nil {
			if proof, ok := reclaimed[key]; ok {
				e = p.openReclaimed(proof, decisions, public)
			} else {
				e = p.openThread(decisions, now)
			}
		}
		if e != nil {
			for _, p := range out {
				_ = p.Close()
			}
			return nil, e
		}
		out[key] = p
	}
	return out, nil
}

// UseJournal は板ワーカーが日付境界で呼ぶ。別所有者・停止済み投稿への切替は拒否する。
func (p *PostingLog) UseJournal(j *evidence.Journal) error {
	if p.stopped || j == nil || j.Owner() != p.owner {
		return errors.New("invalid posting journal switch")
	}
	p.active = j
	return nil
}

// CreateRetry は板内のcreate操作に限り、復旧した再送情報を照合する。
func (p *PostingLog) CreateRetry(want *domain.Dedup, now domain.Time) (PostingResult, bool) {
	if want == nil || p.thread == nil && p.reclaimed == nil {
		return PostingResult{}, false
	}
	record, ok := p.firstRecord()
	if !ok || record.Type != "create" {
		return PostingResult{}, false
	}
	return p.Retry(want, now)
}

// CheckPostingKeys は記録だけが参照するキーも予約高水位内か確認する。
func CheckPostingKeys(journals []*evidence.Journal, watermark uint64) error {
	if len(journals) == 0 {
		return nil
	}
	if journals[0] == nil {
		return ErrEvidenceGap
	}
	owner := journals[0].Owner()
	seen := map[*evidence.Journal]bool{}
	for _, j := range journals {
		if j == nil || j.Owner() != owner || seen[j] {
			return ErrEvidenceGap
		}
		seen[j] = true
		if e := checkJournalPostingKeys(j, watermark); e != nil {
			return e
		}
	}
	return nil
}

// OperationIDs は受理・未受理のproposal ID再利用を防ぐ所有ワーカー向けの一覧。
func (p *PostingLog) OperationIDs() []domain.ID {
	ids := make([]domain.ID, 0, len(p.proposals))
	for id := range p.proposals {
		ids = append(ids, id)
	}
	return ids
}

// CreateDedup は期限内の初回操作の再送情報を所有ワーカーへ返す。公開DTOではない。
func (p *PostingLog) CreateDedup(now domain.Time) *domain.Dedup {
	if p.thread == nil && p.reclaimed == nil {
		return nil
	}
	record, ok := p.firstRecord()
	if !ok || record.Type != "create" || record.Dedup == nil || now >= record.Dedup.Expires {
		return nil
	}
	d := *record.Dedup
	if d.RequestID != nil {
		id := *d.RequestID
		d.RequestID = &id
	}
	return &d
}
