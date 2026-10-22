// 案件管理履歴を回収する前に、site台帳へ登録する私有情報なしの固定一覧を署名する。
package disclosure

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"slices"
	"time"
)

// CaseRetirementIntent は削除前の固定記録。案件IDそのものは保存せず専用HMACに置換する。
// site台帳へ先行登録するための値であり、物理回収完了を表さない。
type CaseRetirementIntent struct {
	Schema          string               `json:"schema"`
	Owner           domain.ID            `json:"source_owner_id"`
	Subkey          domain.U64           `json:"source_subkey"`
	Seq             domain.U64           `json:"source_control_seq"`
	At              domain.Time          `json:"prepared_at_ns"`
	Fingerprint     domain.Hash          `json:"case_hmac"`
	Revision        domain.U64           `json:"case_revision"`
	Head            domain.Hash          `json:"case_audit_sha256"`
	EligibleAt      domain.Time          `json:"eligible_at_ns"`
	Clock           domain.Time          `json:"audit_clock_floor_ns"`
	RequiredRelease domain.Hash          `json:"required_release_sha256"`
	HTTPRelease     domain.Hash          `json:"http_release_sha256"`
	Files           []CaseRetirementFile `json:"files"`
}

// BuildCaseRetirementIntent は元の現在解除/全案件履歴を照合し、サイト台帳へ先行保存する署名記録を作る。
// 共通排他と検査済み元snapshotを必要とする。保存や物理回収は呼出元が行う。
func (s *Store) BuildCaseRetirementIntent(ctx context.Context, candidate CaseRetirementCandidate, required []app.RequiredHoldReceipt, optional []evidence.OptionalHoldReceipt, now time.Time) (CaseRetirementIntent, evidence.Event, error) {
	if e := ctx.Err(); e != nil {
		return CaseRetirementIntent{}, evidence.Event{}, e
	}
	if e := CheckCaseRetirementSources(candidate, required, optional, domain.Time(now.UnixNano())); e != nil {
		return CaseRetirementIntent{}, evidence.Event{}, e
	}
	plans, e := s.PlanCaseRetirement(now)
	if e != nil {
		return CaseRetirementIntent{}, evidence.Event{}, e
	}
	if !slices.Contains(plans, candidate) {
		return CaseRetirementIntent{}, evidence.Event{}, ErrRevision
	}
	files, e := s.InspectCaseRetirementFiles(ctx, candidate, now)
	if e != nil {
		return CaseRetirementIntent{}, evidence.Event{}, e
	}
	intent, event, e := s.sealRetirementIntent(s.retirementIntent(candidate, files, now))
	return intent, event, e
}

// CaseRetirementFingerprint は保存済み回収記録と案件/元参照を対応させる専用HMACを返す。
func (s *Store) CaseRetirementFingerprint(id domain.ID) domain.Hash {
	return s.mac("case-retirement-v1", id[:])
}

// CaseRetirementFingerprint は保存所有者を開かず元の案件IDを専用HMACへ対応させる。
// 不正な鍵長やゼロ案件IDは拒否する。
func CaseRetirementFingerprint(key ed25519.PrivateKey, id domain.ID) (domain.Hash, error) {
	if len(key) != ed25519.PrivateKeySize || id == (domain.ID{}) {
		return domain.Hash{}, ErrInvalid
	}
	s := &Store{key: key}
	return s.CaseRetirementFingerprint(id), nil
}

// VerifyCaseRetirementIntent は現在所有者の専用公開鍵で登録済み固定記録を照合する。
func (s *Store) VerifyCaseRetirementIntent(event evidence.Event, fingerprint domain.Hash) (CaseRetirementIntent, error) {
	return VerifyCaseRetirementIntent(event, fingerprint, s.key.Public().(ed25519.PublicKey))
}

func (s *Store) retirementIntent(candidate CaseRetirementCandidate, files []CaseRetirementFile, now time.Time) CaseRetirementIntent {
	fingerprint := s.CaseRetirementFingerprint(candidate.Case)
	var owner domain.ID
	copy(owner[:], fingerprint[:16])
	return CaseRetirementIntent{Schema: "case-retirement-v1", Owner: owner, Seq: 1, At: domain.Time(now.UnixNano()), Fingerprint: fingerprint, Revision: candidate.Revision, Head: candidate.Head, EligibleAt: candidate.EligibleAt, Clock: candidate.Clock, RequiredRelease: candidate.RequiredRelease, HTTPRelease: candidate.HTTPRelease, Files: files}
}

func (s *Store) sealRetirementIntent(intent CaseRetirementIntent) (CaseRetirementIntent, evidence.Event, error) {
	if e := validateRetirementIntent(intent); e != nil {
		return intent, evidence.Event{}, e
	}
	payload, e := json.Marshal(intent)
	if e != nil {
		return intent, evidence.Event{}, e
	}
	event, e := evidence.Seal(evidence.Source{Owner: intent.Owner, Seq: 1}, intent.Owner, "receipt", payload, domain.Hash{}, 10, s.key)
	if e != nil {
		return intent, event, e
	}
	return intent, event, nil
}

// VerifyCaseRetirementIntent は案件IDなしで登録HMAC/元署名/完全型/固定一覧を検証する。
// 記録の現在登録、元の現在解除、物理削除の完了はこの検証だけでは証明しない。
func VerifyCaseRetirementIntent(event evidence.Event, fingerprint domain.Hash, key ed25519.PublicKey) (CaseRetirementIntent, error) {
	var intent CaseRetirementIntent
	var owner domain.ID
	copy(owner[:], fingerprint[:16])
	if event.RecordID != owner || event.Kind != "receipt" {
		return intent, store.ErrCorrupt
	}
	payload, e := evidence.Verify(evidence.Source{Owner: owner, Seq: 1}, event, domain.Hash{}, 10, key)
	if e != nil || strictjson.Decode(payload, &intent) != nil || intent.Fingerprint != fingerprint {
		return intent, store.ErrCorrupt
	}
	if e = validateRetirementIntent(intent); e != nil {
		return intent, e
	}
	return intent, nil
}

func validateRetirementIntent(intent CaseRetirementIntent) error {
	if e := validateRetirementIntentIdentity(intent); e != nil {
		return e
	}
	if intent.EligibleAt <= 0 || intent.Clock <= 0 || intent.At < max(intent.EligibleAt, intent.Clock) {
		return ErrExpired
	}
	return validateRetirementIntentFiles(intent.Files)
}

func validateRetirementIntentIdentity(intent CaseRetirementIntent) error {
	var owner domain.ID
	copy(owner[:], intent.Fingerprint[:16])
	if intent.Schema != "case-retirement-v1" || intent.Owner == (domain.ID{}) || intent.Owner != owner || intent.Subkey != 0 || intent.Seq != 1 || intent.Revision == 0 || intent.Head == (domain.Hash{}) {
		return store.ErrCorrupt
	}
	return nil
}

func validateRetirementIntentFiles(files []CaseRetirementFile) error {
	if len(files) < 2 || len(files) > maxCaseRetirementFiles {
		return ErrLimit
	}
	var total uint64
	previous := ""
	current := false
	for _, file := range files {
		if e := validateRetirementIntentFile(file, previous); e != nil {
			return e
		}
		if file.Name == "control/control.current" {
			current = true
		}
		total += uint64(file.Bytes)
		if total > uint64(MaxStoredBytes) {
			return ErrLimit
		}
		previous = file.Name
	}
	if !current {
		return store.ErrCorrupt
	}
	return nil
}

func validateRetirementIntentFile(file CaseRetirementFile, previous string) error {
	name := filepath.Base(file.Name)
	if file.Name <= previous || file.Name != "control/"+name || file.Bytes == 0 || uint64(file.Bytes) > uint64(MaxStoredBytes) || file.SHA == (domain.Hash{}) {
		return store.ErrCorrupt
	}
	if name != "control.current" {
		_, _, e := retirementGeneration(name)
		return e
	}
	return nil
}
