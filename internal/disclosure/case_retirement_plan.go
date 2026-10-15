// 閉鎖後180日の管理履歴回収に向け、本文なしの固定候補と解除参照を抽出する。
package disclosure

import (
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"sort"
	"time"
)

const caseMetadataRetention = domain.Time(180 * 24 * time.Hour)

// CaseRetirementCandidate は署名済み最新状態に束縛した管理履歴回収候補。
// 範囲/担当/申立理由/本文/接続は含めない。元所有者との現在照合や物理回収証明の代用にはならない。
type CaseRetirementCandidate struct {
	Case            domain.ID   `json:"case_id"`
	Revision        domain.U64  `json:"case_revision"`
	Head            domain.Hash `json:"case_audit_sha256"`
	EligibleAt      domain.Time `json:"eligible_at_ns"`
	Clock           domain.Time `json:"audit_clock_floor_ns"`
	RequiredRelease domain.Hash `json:"required_release_sha256"`
	HTTPRelease     domain.Hash `json:"http_release_sha256"`
}

// PlanCaseRetirement は全最新監査の時計を検査し、閉鎖後180日を過ぎた候補を固定順で返す。
// 案件排他内で呼ぶ。期限到達案件のコピー/元解除が未完了なら全体を非変更で拒否する。
// この操作は署名追加/物理削除/保存枠の解放を行わない。
func (s *Store) PlanCaseRetirement(now time.Time) ([]CaseRetirementCandidate, error) {
	at := domain.Time(now.UnixNano())
	if s.stopped || at <= 0 {
		return nil, ErrInvalid
	}
	result := []CaseRetirementCandidate{}
	for id := range s.logs {
		a, event, e := s.lastAuditEvent(id)
		if e != nil {
			return nil, e
		}
		if at < a.At {
			return nil, ErrExpired
		}
		candidate, ready, e := planCaseRetirement(a, event, at)
		if e != nil {
			return nil, e
		}
		if ready {
			result = append(result, candidate)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Case.String() < result[j].Case.String() })
	return result, nil
}

// planCaseRetirement は満了日時の加算溢れを拒否し、最新署名と期限へ候補を束縛する。
func planCaseRetirement(a Audit, event evidence.Event, at domain.Time) (CaseRetirementCandidate, bool, error) {
	c := a.Case
	if c.State != "closed" {
		return CaseRetirementCandidate{}, false, nil
	}
	if c.Closed <= 0 || c.Closed > domain.Time(math.MaxInt64)-caseMetadataRetention {
		return CaseRetirementCandidate{}, false, ErrInvalid
	}
	deadline := c.Closed + caseMetadataRetention
	if at < deadline {
		return CaseRetirementCandidate{}, false, nil
	}
	if e := caseRetirementCopiesRemoved(c); e != nil {
		return CaseRetirementCandidate{}, false, e
	}
	candidate := CaseRetirementCandidate{Case: c.ID, Revision: a.Seq, Head: event.EventSHA, EligibleAt: deadline, Clock: a.At}
	if e := bindCaseRetirementReleases(c, &candidate); e != nil {
		return CaseRetirementCandidate{}, false, e
	}
	return candidate, true, nil
}

// caseRetirementCopiesRemoved は全保全コピー/ZIPの署名状態が回収済みであることを要求する。
// fileと元所有者の現在状態は後段の回収処理が別途照合する。
func caseRetirementCopiesRemoved(c Case) error {
	for _, item := range c.Items {
		if item.State != "removed" {
			return store.ErrIncomplete
		}
	}
	for _, export := range c.Exports {
		if export.State != "removed" {
			return store.ErrIncomplete
		}
	}
	return caseRetirementHTTPRemoved(c.HTTP)
}

// bindCaseRetirementReleases は元予約がある案件の耐久解除参照を必須にする。
func bindCaseRetirementReleases(c Case, candidate *CaseRetirementCandidate) error {
	if c.Required != nil {
		if c.Required.Released == nil {
			return store.ErrIncomplete
		}
		candidate.RequiredRelease = c.Required.Released.SHA
	}
	if c.HTTP != nil {
		if c.HTTP.Released != nil {
			candidate.HTTPRelease = c.HTTP.Released.SHA
		} else if c.HTTP.Reservation != nil {
			return store.ErrIncomplete
		}
	}
	return nil
}

// caseRetirementHTTPRemoved は任意HTTPコピーの全項目も回収済みであることを確認する。
func caseRetirementHTTPRemoved(h *HTTPHold) error {
	if h == nil {
		return nil
	}
	if h.State != "removed" {
		return store.ErrIncomplete
	}
	for _, item := range h.Items {
		if item.State != "removed" {
			return store.ErrIncomplete
		}
	}
	return nil
}
