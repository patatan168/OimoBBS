// 公開本体回収後にも、照合済み受理frameから本文なし監査要約を取り出す。
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// ThreadAudit は確定操作の要約だけを返す。since以下の時刻の操作を含めない。
// 元frameのSHA/seq/時刻を検査し、本文・IP・タイトル・移転先URLを値へコピーしない。
func (p *PostingLog) ThreadAudit(since domain.Time) ([]store.PackAudit, error) {
	out := []store.PackAudit{}
	for _, r := range p.records() {
		if r.Committed <= since {
			continue
		}
		entry, ok := p.proposals[r.ID]
		if !ok || entry.payload.ThreadSeq != r.Seq || entry.payload.FrameSHA != r.FrameSHA {
			return nil, ErrEvidenceGap
		}
		raw, e := entry.decodeFrame()
		if e != nil || sha256.Sum256(raw) != r.FrameSHA {
			return nil, ErrEvidenceGap
		}
		frame, n, e := store.ReadFrame(bytes.NewReader(raw))
		if e != nil || n != int64(len(raw)) || len(frame.Records) != 1 || frame.Records[0].ID != r.ID {
			return nil, ErrEvidenceGap
		}
		op, e := domain.ParseOperation(frame.Records[0].JSON)
		if e != nil || op.Revision != r.Seq || op.Committed != r.Committed || op.Type != r.Type || op.Committed > domain.Time(math.MaxInt64)-domain.Time(180*24*3600e9) {
			return nil, ErrEvidenceGap
		}
		var payload struct {
			Posts []domain.Post `json:"posts"`
		}
		if e = json.Unmarshal(op.Payload, &payload); e != nil {
			return nil, e
		}
		ranges := []store.PackRange{}
		for _, post := range payload.Posts {
			if len(ranges) > 0 && ranges[len(ranges)-1].Last+1 == post.Number {
				ranges[len(ranges)-1].Last = post.Number
			} else {
				ranges = append(ranges, store.PackRange{First: post.Number, Last: post.Number})
			}
		}
		out = append(out, store.PackAudit{Seq: r.Seq, ID: r.ID, Type: r.Type, Committed: r.Committed, Actor: op.Actor, Versions: op.Versions, Ranges: ranges, Expires: op.Committed + domain.Time(180*24*3600e9)})
	}
	return out, nil
}
