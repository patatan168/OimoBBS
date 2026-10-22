// 接続観測の板が受理原本と違う場合、要求メタデータを提出しないことを検査する。
package app

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
)

func TestAcceptedRequestMetadataRejectsDifferentBoard(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	var p postingProposal
	if e := json.Unmarshal(r.Proposal.Payload, &p); e != nil {
		t.Fatal(e)
	}
	obs := &evidence.HTTPObservation{BoardID: domain.NewID()}
	if _, _, e := projectAcceptedRequestMetadata(r, p, obs, nil); e != ErrEvidenceGap {
		t.Fatal("other board observation adopted", e)
	}
}
