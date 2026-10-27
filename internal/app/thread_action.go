// 管理者のスレッド状態変更を、既存の署名付き管理frameへ変換する。
package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// ThreadActionInput は所有列で検証する認可済み入力。終了レスは板設定から渡す。
type ThreadActionInput struct {
	ID           domain.ID
	Kind, Target string
	Policy       *domain.Policy
	Ending       domain.Post
	Expected     domain.U64
	Actor        domain.Actor
	Versions     domain.Versions
	Now          domain.Time
}

// ThreadActionState は本文・接続情報を含まない管理対象の現在値を返す。
func (p *PostingLog) ThreadActionState() (domain.U64, domain.Time, domain.Policy, string, error) {
	if p.reclaimed != nil {
		v := p.reclaimed.proof
		policy := v.Policy
		policy.Commands = append([]string{}, policy.Commands...)
		return v.Sequence, v.Expires, policy, v.After.State, nil
	}
	if p.stopped || p.thread == nil {
		return 0, 0, domain.Policy{}, "", ErrEvidenceGap
	}
	s := p.thread.State()
	policy := s.Policy
	policy.Commands = append([]string{}, policy.Commands...)
	return s.Revision, s.Expires, policy, s.After.State, nil
}

// PrepareThreadAction は旧状態を変更せず、管理操作のDATと遷移を検算する。
func (p *PostingLog) PrepareThreadAction(in ThreadActionInput) ([]byte, error) {
	if p.stopped || p.expired || p.thread == nil || in.ID == (domain.ID{}) || in.Actor.Kind != "admin" {
		return nil, ErrEvidenceGap
	}
	s := p.thread.State()
	if s.Revision != in.Expected || in.Now >= s.Expires {
		return nil, domain.ErrOperation
	}
	after := s.After
	var payload any
	var dat []byte
	switch in.Kind {
	case "stop":
		post := in.Ending
		post.Number, post.Kind, post.Visibility, post.Created = s.After.PostCount+1, "system", "visible", in.Now
		post.Identity = domain.Identity{DateText: compat.DateText(time.Unix(0, int64(in.Now)))}
		post.Private, post.DATOffset = nil, 0
		var err error
		dat, err = compat.DAT(post, "")
		if err != nil {
			return nil, err
		}
		post.DATLength = uint32(len(dat))
		after.PostCount++
		after.DATBytes += domain.U64(len(dat))
		after.State = "stopped"
		reason := "manual"
		after.EndReason = &reason
		payload = domain.Stop{Posts: []domain.Post{post}, Reason: reason}
	case "archive":
		reason := "manual"
		after.State, after.EndReason = "archived", &reason
		payload = domain.Archive{Reason: reason}
	case "move_link":
		payload = domain.Move{Target: in.Target}
	case "update_policy":
		if in.Policy == nil {
			return nil, domain.ErrOperation
		}
		policy := *in.Policy
		if policy.Version != s.Policy.Version || (len(policy.Commands) != 0 && !slices.Equal(policy.Commands, s.Policy.Commands)) || policy.UserPostLimit <= s.After.UserCount || policy.DATUserLimit <= s.After.DATBytes {
			return nil, domain.ErrOperation
		}
		policy.Version = s.Policy.Version + 1
		payload = domain.UpdatePolicy{Policy: policy}
	default:
		return nil, domain.ErrOperation
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	versions := in.Versions
	versions.Thread = s.Policy.Version
	op := domain.Operation{Type: in.Kind, Revision: s.Revision + 1, Committed: in.Now, Versions: versions, Actor: in.Actor, After: after, Payload: raw}
	raw, err = json.Marshal(op)
	if err != nil {
		return nil, err
	}
	frame, err := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Revision), Records: []store.Record{{ID: in.ID, JSON: raw, DAT: dat}}})
	if err == nil {
		_, err = store.ValidateThreadFrame(s, frame)
	}
	return frame, err
}

// AdministrativeApplied は固定ID・位置・frame全体を署名済みproposalと確定記録へ照合する。
func (p *PostingLog) AdministrativeApplied(id domain.ID, revision domain.U64, frame []byte) bool {
	if p.thread == nil && p.reclaimed == nil {
		return false
	}
	entry, ok := p.proposals[id]
	digest := sha256.Sum256(frame)
	if !ok || entry.event.Kind != "thread_admin_proposal" || entry.payload.FrameSHA != digest {
		return false
	}
	saved, err := base64.StdEncoding.Strict().DecodeString(entry.payload.Frame)
	if err != nil || sha256.Sum256(saved) != digest {
		return false
	}
	for _, record := range p.records() {
		if record.ID == id && record.Seq == revision && record.FrameSHA == digest {
			return true
		}
	}
	return false
}
