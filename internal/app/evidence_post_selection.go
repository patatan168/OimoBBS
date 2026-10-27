// 管理人がレス番号から記録を選ぶ。公開IDを主体HMACへ読み替えない。
package app

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// ErrEvidenceIdentityUnavailable は記録のないIP/匿名主体の関連照会を表す。
var ErrEvidenceIdentityUnavailable = errors.New("evidence identity not recorded")

// EvidencePostIdentity は保存時に確認した接続IP・UA・匿名主体だけを持つ非公開情報。
type EvidencePostIdentity struct {
	IP      string
	Agents  []string
	Subject domain.Hash
	Cap     domain.ID
}

// Identity は署名検証済み受理原本の保存値を返す。Cookieや秘密入力を返さない。
func (r AcceptedEvidence) Identity() (EvidencePostIdentity, error) {
	var p postingProposal
	if err := json.Unmarshal(r.Proposal.Payload, &p); err != nil {
		return EvidencePostIdentity{}, err
	}
	return proposalIdentity(p)
}

// proposalIdentity は保存された観測と検証済み匿名資格だけを識別情報へ投影する。
func proposalIdentity(p postingProposal) (EvidencePostIdentity, error) {
	var identity EvidencePostIdentity
	obs, err := evidence.PostingHTTPObservation(p.Capture)
	if err != nil {
		return identity, err
	}
	if obs != nil {
		identity.IP = obs.Resolved.IP
		for _, h := range obs.SelectedHeaders {
			if h.Name == "User-Agent" {
				for _, value := range h.Values {
					identity.Agents = append(identity.Agents, value.Display)
				}
			}
		}
	}
	var capture map[string]json.RawMessage
	if err = json.Unmarshal(p.Capture, &capture); err != nil {
		return identity, err
	}
	principal, err := projectPrincipalIdentity(capture)
	if err != nil {
		return identity, err
	}
	if value, ok := principal["anon_subject_hmac"].(domain.Hash); ok {
		identity.Subject = value
	}
	if value, ok := principal["cap_id"].(domain.ID); ok {
		identity.Cap = value
	}
	return identity, nil
}

// ReportBody は受理原本の秘密除去済み本文を自動通報判定へ渡す。公開応答には使わない。
func (r AcceptedEvidence) ReportBody() (string, error) {
	var p postingProposal
	if err := json.Unmarshal(r.Proposal.Payload, &p); err != nil {
		return "", err
	}
	var capture struct {
		Input struct {
			Body string `json:"body"`
		} `json:"input"`
	}
	if err := json.Unmarshal(p.Capture, &capture); err != nil {
		return "", err
	}
	return capture.Input.Body, nil
}

// AcceptedRecordsForPost は一レス、または同一板・スレッド内の同じIP/匿名主体を選ぶ。
// 期限切れ・未受理を含めず、件数/8MiB上限を超える一致を黙って切り捨てない。relatedはpost/ip/token。
func AcceptedRecordsForPost(journals []*evidence.Journal, owner domain.ID, thread domain.U64, post uint32, related string, now domain.Time, limit int) ([]AcceptedEvidence, error) {
	match := func(board domain.ID, key domain.U64, at domain.Time, id domain.ID) bool {
		return board == owner && key == thread && at <= now && postRetention(at) > now
	}
	anchor, err := acceptedRecordsFiltered(journals, match, func(p postingProposal) (bool, error) {
		_, op, err := acceptedEvidenceFrame(p)
		if err != nil {
			return false, err
		}
		return op.Dedup != nil && op.Dedup.PostNumber == post, nil
	}, 1)
	if err != nil || len(anchor) != 1 || related == "post" {
		return anchor, err
	}
	identity, err := anchor[0].Identity()
	if err != nil {
		return nil, err
	}
	if related != "ip" && related != "token" || related == "ip" && identity.IP == "" || related == "token" && identity.Subject == (domain.Hash{}) {
		return nil, ErrEvidenceIdentityUnavailable
	}
	return acceptedRecordsFiltered(journals, match, func(p postingProposal) (bool, error) {
		candidate, err := proposalIdentity(p)
		if err != nil {
			return false, err
		}
		if related == "ip" {
			return candidate.IP == identity.IP, nil
		}
		return candidate.Subject == identity.Subject, nil
	}, limit)
}
