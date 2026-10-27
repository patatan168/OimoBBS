// 共有本文WALの各frameを検証済み必須記録へ結び、公開起動前だけ再実行を許可する。
package app

import (
	"crypto/sha256"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
)

// RecoverPostingGroup は全期間の署名検証済みjournalを使い、未checkpointの本文を復旧する。
// 通常の投稿復旧より先に呼び、未受理と確定した操作や原本のないframeは再実行しない。
func RecoverPostingGroup(parent string, owner domain.ID, journals []*evidence.Journal) error {
	if _, err := os.Lstat(filepath.Join(parent, store.ThreadGroupFile)); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	proposals := map[domain.ID]proposalEntry{}
	decisions := map[domain.ID]postingDecision{}
	for _, journal := range journals {
		if journal == nil || journal.Owner() != owner {
			return ErrEvidenceGap
		}
		for _, entry := range journal.Entries() {
			switch entry.Event.Kind {
			case "evidence_proposal":
				var proposal postingProposal
				if strictjson.Decode(entry.Payload, &proposal) != nil || proposals[proposal.OperationID].payload.OperationID != (domain.ID{}) {
					return ErrEvidenceGap
				}
				proposals[proposal.OperationID] = proposalEntry{payload: proposal, event: entry.Event}
			case "evidence_decision":
				var decision postingDecision
				if strictjson.Decode(entry.Payload, &decision) != nil || decisions[decision.OperationID].OperationID != (domain.ID{}) {
					return ErrEvidenceGap
				}
				decisions[decision.OperationID] = decision
			}
		}
	}
	return store.RecoverThreadCommitGroup(parent, owner, func(key uint64, raw []byte) error {
		frame, op, err := postingFrame(raw)
		if err != nil || op.Type != "append" {
			return ErrEvidenceGap
		}
		entry, exists := proposals[frame.Records[0].ID]
		proposal := entry.payload
		if !exists || proposal.Owner != owner || uint64(proposal.ThreadKey) != key || proposal.FrameSHA != sha256.Sum256(raw) || proposal.ThreadSeq != op.Revision || proposal.Committed != op.Committed {
			return ErrEvidenceGap
		}
		if decision, exists := decisions[proposal.OperationID]; exists && (decision.Outcome != "accepted" || !decision.matches(proposal, entry.event)) {
			return ErrEvidenceGap
		}
		return nil
	})
}
