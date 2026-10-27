// 規制復旧に必要な非公開項目だけを、所有ワーカーへコピーする。
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

// RateRecord は規制復元専用の非公開データ。HTTP DTOや一般ログへ渡さない。
type RateRecord struct {
	Schema, TokenStatus string
	Token               *postcapture.TokenEvidence
	ID                  domain.ID
	PostNumber          uint32
	At                  domain.Time
	Create              bool
	IP                  string
	Keys                []domain.RateKey
	Overrides           []domain.ID
	Retirement          *RateRetirementProof `json:"-"`
}

// FrameRateRecord は通常投稿frameの先頭ユーザー投稿から規制情報を読む。
func FrameRateRecord(raw []byte) (RateRecord, error) {
	f, n, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil || n != int64(len(raw)) || len(f.Records) != 1 {
		return RateRecord{}, store.ErrCorrupt
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		return RateRecord{}, e
	}
	return parsedFrameRateRecord(f, op)
}

// parsedFrameRateRecord は同じ呼出し内で復号済みのframe・操作から規制成分を複製する。
func parsedFrameRateRecord(f store.Frame, op domain.Operation) (RateRecord, error) {
	var e error
	var posts []domain.Post
	switch op.Type {
	case "create":
		var c domain.Create
		e = json.Unmarshal(op.Payload, &c)
		posts = c.Posts
	case "append":
		var c domain.Append
		e = json.Unmarshal(op.Payload, &c)
		posts = c.Posts
	default:
		return RateRecord{}, store.ErrCorrupt
	}
	if e != nil || len(posts) == 0 || posts[0].Kind != "user" || posts[0].Private == nil {
		return RateRecord{}, store.ErrCorrupt
	}
	p := posts[0].Private
	return RateRecord{ID: f.Records[0].ID, PostNumber: posts[0].Number, At: op.Committed, Create: op.Type == "create", IP: p.SourceIP, Keys: append([]domain.RateKey{}, p.RateKeys...)}, nil
}

// RateHistory は公開期限に依存せず、受理裁定済みの履歴を返す。復旧完了後の所有者専用。
func (p *PostingLog) RateHistory() ([]RateRecord, error) {
	if p.hasExpiredBodyCarry() {
		return []RateRecord{}, nil
	}
	if p.thread == nil && p.reclaimed == nil {
		return nil, nil
	}
	rows := []RateRecord{}
	var carried map[domain.ID]RateCarry
	if p.reclaimed != nil && p.reclaimed.carry != nil {
		carried = map[domain.ID]RateCarry{}
		for _, v := range p.reclaimed.carry.Rates {
			carried[v.ID] = v
		}
	}
	for _, r := range p.records() {
		if r.Type != "create" && r.Type != "append" {
			continue
		}
		if retired, ok := p.retired[r.ID]; ok && retired.proposal != nil {
			rate, found := carried[r.ID]
			v, e := p.retiredRateRecord(r, rate, found)
			if e != nil {
				return nil, e
			}
			rows = append(rows, v)
			continue
		}
		// 再送索引の30秒満了と受理枠の61分保持を分離する。
		// 現行packが満了済みDedupを捨てても、照合済みの元proposalから復元する。
		entry, ok := p.proposals[r.ID]
		if !ok || entry.payload.FrameSHA != r.FrameSHA || entry.payload.ThreadSeq != r.Seq || entry.payload.Committed != r.Committed {
			return nil, ErrEvidenceGap
		}
		raw, e := entry.decodeFrame()
		if e != nil || domain.Hash(sha256.Sum256(raw)) != r.FrameSHA {
			return nil, ErrEvidenceGap
		}
		v, e := FrameRateRecord(raw)
		if e != nil || v.ID != r.ID || v.At != r.Committed {
			return nil, ErrEvidenceGap
		}
		capture, e := entry.originalCapture()
		if e != nil {
			return nil, e
		}
		v.Schema, v.TokenStatus, v.Token, e = postcapture.TokenMetadata(capture)
		if e != nil {
			return nil, e
		}
		_, _, v.Overrides, e = postcapture.OverrideMetadata(capture)
		if e != nil {
			return nil, e
		}
		if carried != nil {
			if rate, ok := carried[r.ID]; ok {
				v.Keys = append([]domain.RateKey{}, rate.Keys...)
			} else if p.reclaimed.proof.Schema == 2 {
				return nil, ErrEvidenceGap
			}
		}
		rows = append(rows, v)
	}
	return rows, nil
}
