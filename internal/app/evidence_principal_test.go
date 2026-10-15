// 主体選択が原本の受理枠ルールだけを返し、本文や接続情報を混ぜないことを検査する。
package app

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"slices"
	"testing"
)

func TestAcceptedPrincipalIncludesCommittedRateRules(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	// capture側に同名の値があっても、ルールIDの根拠は確定操作だけとする。
	var p postingProposal
	if e := json.Unmarshal(r.Proposal.Payload, &p); e != nil {
		t.Fatal(e)
	}
	p.Capture = json.RawMessage(`{"rule_ids":["ffffffffffffffffffffffffffffffff"],"credential":"SECRET_CREDENTIAL"}`)
	r.Proposal.Payload, _ = json.Marshal(p)
	selected, e := r.Project([]string{"principal"})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(selected)
	if e != nil {
		t.Fatal(e)
	}
	var row struct {
		Principal struct {
			Rules []domain.ID `json:"rule_ids"`
		} `json:"principal"`
	}
	if e = json.Unmarshal(raw, &row); e != nil {
		t.Fatal(e)
	}
	if len(row.Principal.Rules) != 1 || row.Principal.Rules[0].String() != "aabbccddeeff00112233445566778899" {
		t.Fatal("saved admission rule omitted", string(raw))
	}
	assertPrincipalPrivacy(t, raw)
	metadata, e := r.Project(nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, found := metadata["principal"]; found {
		t.Fatal("unselected principal disclosed")
	}
}

func assertPrincipalPrivacy(t *testing.T, raw []byte) {
	t.Helper()
	for _, secret := range []string{`"content"`, `"connection"`, `"private"`, `"source_ip"`, `"rate_keys"`, "SECRET_CREDENTIAL", "prepared_frame_base64", "1111111111111111111111111111111111111111111111111111111111111111"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("unselected data disclosed", secret)
		}
	}
}

func TestAcceptedPrincipalRejectsChangedFrameBinding(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	var p postingProposal
	if e := json.Unmarshal(r.Proposal.Payload, &p); e != nil {
		t.Fatal(e)
	}
	p.FrameSHA[0] ^= 1
	r.Proposal.Payload, _ = json.Marshal(p)
	if _, e := r.Project([]string{"principal"}); e != ErrEvidenceGap {
		t.Fatal("changed original accepted", e)
	}
}

func TestAcceptedRateRulesAreStableAndUnique(t *testing.T) {
	first, second := domain.ID{1}, domain.ID{2}
	posts := []domain.Post{{Private: nil}, {Private: &domain.Private{RateKeys: []domain.RateKey{{Rule: second}, {Rule: first}}}}, {Private: &domain.Private{RateKeys: []domain.RateKey{{Rule: second}}}}}
	if ids := acceptedRateRuleIDs(posts); !slices.Equal(ids, []domain.ID{first, second}) {
		t.Fatal("unstable or duplicate rules", ids)
	}
	if ids := acceptedRateRuleIDs(nil); ids == nil || len(ids) != 0 {
		t.Fatal("empty rules must be an array")
	}
}
