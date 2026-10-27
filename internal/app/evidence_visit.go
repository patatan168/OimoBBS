// 受理原本を一件ずつ照合し、受付再開時に本文全件の複製を避ける。
package app

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/strictjson"
)

// VisitAcceptedRecordsInRange は所有列内で受理decisionと署名済みproposalを照合する。
// callbackは所有列を変更せず、必要な値だけを複製する。件数による切捨てを行わない。
func VisitAcceptedRecordsInRange(journals []*evidence.Journal, match func(domain.ID, domain.U64, domain.Time, domain.ID) bool, visit func(AcceptedEvidence) error) error {
	seen := make(map[domain.ID]bool)
	for _, journal := range journals {
		if err := journal.Visit(func(entry evidence.Entry) error {
			if entry.Event.Kind != "evidence_decision" {
				return nil
			}
			var decision postingDecision
			if err := strictjson.Decode(entry.Payload, &decision); err != nil {
				return err
			}
			if decision.Outcome != "accepted" || !match(decision.Owner, decision.ThreadKey, decision.Committed, decision.ProposalID) {
				return nil
			}
			source, found, err := journal.Lookup(decision.ProposalID)
			if err != nil {
				return err
			}
			if !found || source.Event.Kind != "evidence_proposal" || seen[decision.OperationID] {
				return ErrEvidenceGap
			}
			var proposal postingProposal
			if err := strictjson.Decode(source.Payload, &proposal); err != nil {
				return err
			}
			if !decision.matches(proposal, source.Event) {
				return ErrEvidenceGap
			}
			_, operation, err := acceptedEvidenceFrame(proposal)
			if err != nil {
				return err
			}
			if operation.Dedup == nil {
				return ErrEvidenceGap
			}
			seen[decision.OperationID] = true
			return visit(AcceptedEvidence{source.Event.RecordID, proposal.Owner, proposal.ThreadKey, proposal.OperationID, operation.Dedup.PostNumber, proposal.Committed, proposal.Retention, source, entry})
		}); err != nil {
			return err
		}
	}
	return nil
}
