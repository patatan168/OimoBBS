// 元の解除正本を再照合し、案件一件を外す署名索引候補を保存せず構成する。
package evidence

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// OptionalHoldRetirementCandidate は所有者が構成した索引置換候補。構成だけでは枠を解放しない。
// Previousは現在索引、Nextは元解除と現在サイト回収登録へ束縛された一件除去候補。
type OptionalHoldRetirementCandidate struct {
	Previous Event
	Next     Event
}

type optionalHoldIndexRetirement struct {
	Case         domain.ID   `json:"case_id"`
	Fingerprint  domain.Hash `json:"case_hmac"`
	Release      domain.Hash `json:"http_release_sha256"`
	Registration domain.Hash `json:"case_retirement_sha256"`
}

type optionalHoldRetirementIndexPayload struct {
	Owner      domain.ID                    `json:"source_owner_id"`
	Subkey     domain.U64                   `json:"source_subkey"`
	Schema     string                       `json:"schema"`
	Site       domain.ID                    `json:"site_id"`
	Sequence   domain.U64                   `json:"source_control_seq"`
	At         domain.Time                  `json:"recorded_at_ns"`
	Cases      []domain.ID                  `json:"case_ids"`
	Retirement *optionalHoldIndexRetirement `json:"retirement"`
}

// PrepareOptionalHoldRetirement は所有排他内で現在解除とdisk正本を照合し、署名候補を返す。
// 呼出元は最新サイト登録と案件の物理回収完了を先に検査する。登録hashだけを削除許可にはしない。
// 保存・unlink・候補復旧は行わず、時計逆行/古い参照/未確定保存を拒否する。
func (s *OptionalStore) PrepareOptionalHoldRetirement(ctx context.Context, released OptionalHoldReceipt, fingerprint, registration domain.Hash, now time.Time) (OptionalHoldRetirementCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return OptionalHoldRetirementCandidate{}, err
	}
	if err := s.checkOptionalHoldRelease(released); err != nil {
		return OptionalHoldRetirementCandidate{}, err
	}
	if err := s.checkOptionalRetirementDisk(released.Binding.Case); err != nil {
		return OptionalHoldRetirementCandidate{}, err
	}
	payload, err := buildOptionalHoldRetirementIndex(s.holdIndex, released, fingerprint, registration, domain.Time(now.UnixNano()), s.floor)
	if err != nil {
		return OptionalHoldRetirementCandidate{}, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return OptionalHoldRetirementCandidate{}, err
	}
	next, err := Seal(Source{payload.Owner, 0, uint64(payload.Sequence)}, s.site, "checkpoint", body, s.holdIndex.event.EventSHA, 10, s.key)
	if err != nil {
		return OptionalHoldRetirementCandidate{}, err
	}
	return OptionalHoldRetirementCandidate{s.holdIndex.event, next}, nil
}

// checkOptionalRetirementDisk は候補なしの現在索引/解除bytesを照合し、外部差替えを採用しない。
func (s *OptionalStore) checkOptionalRetirementDisk(id domain.ID) error {
	index, err := s.loadOptionalHoldIndex(true)
	if err != nil {
		return err
	}
	if !equalOptionalHoldBytes(index.event, s.holdIndex.event) {
		return store.ErrCorrupt
	}
	if _, err := os.Lstat(s.holdFile(id) + ".pending"); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return store.ErrIncomplete
	}
	raw, err := readOptionalPrivate(filepath.Join(s.root, optionalHoldsDir, id.String()+".json"), optionalHoldFileLimit)
	if err != nil {
		return err
	}
	released, err := s.decodeOptionalHold(raw, id)
	if err != nil {
		return err
	}
	if !equalOptionalHoldBytes(released.event, s.holds[id].event) {
		return store.ErrCorrupt
	}
	return nil
}

// buildOptionalHoldRetirementIndex は一件だけを外し、集合の独立所有と連続seq/解除hashを固定する。
func buildOptionalHoldRetirementIndex(old optionalHoldIndexSaved, released OptionalHoldReceipt, fingerprint, registration domain.Hash, now, floor domain.Time) (optionalHoldRetirementIndexPayload, error) {
	var result optionalHoldRetirementIndexPayload
	if fingerprint == (domain.Hash{}) || registration == (domain.Hash{}) || old.payload.Sequence == 0 || old.payload.Sequence == domain.U64(math.MaxUint64) || !slices.Contains(old.payload.Cases, released.Binding.Case) {
		return result, store.ErrCorrupt
	}
	if now <= 0 || now < max(floor, old.payload.At, released.At) {
		return result, ErrRetirementClock
	}
	p := old.payload
	p.Schema = "optional-http-hold-index-v2"
	p.Sequence++
	p.At = now
	p.Cases = slices.DeleteFunc(slices.Clone(p.Cases), func(id domain.ID) bool { return id == released.Binding.Case })
	if p.Cases == nil {
		p.Cases = []domain.ID{}
	}
	result = optionalRetirementIndexPayload(p, &optionalHoldIndexRetirement{released.Binding.Case, fingerprint, released.SHA, registration})
	return result, nil
}
