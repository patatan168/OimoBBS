// 連鎖hashを所有列で確定した後、独立した署名・frame符号化をCPU数以内で分担する。
package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"oimobbs/internal/parallel"
	"oimobbs/internal/store"
)

// prepareBatchFrames は各slotだけを書き、全workerを待って要求順の最初のエラーを返す。
// journal状態とfileは変更せず、元payload・source・鍵の検査はprepareSealで済ませる。
func (j *Journal) prepareBatchFrames(entries []Entry, requests []AppendRequest, concurrent bool) ([][]byte, error) {
	frames := make([][]byte, len(entries))
	errs := make([]error, len(entries))
	encode := func(i int) {
		event := &entries[i].Event
		signature := ed25519.Sign(j.key, event.EventSHA[:])
		event.Signature = base64.StdEncoding.EncodeToString(signature)
		seq := j.seq + uint64(i) + 1
		id := requests[i].ID
		raw, _, err := marshalJournalOperation(*event, entries[i].Payload, signature, seq, requests[i].Committed, false)
		if err != nil {
			errs[i] = err
			return
		}
		frames[i], errs[i] = store.EncodeFrame(store.Frame{FirstSeq: seq, Records: []store.Record{{ID: id, JSON: raw}}})
	}
	if concurrent {
		parallel.CPU(len(entries), encode)
	} else {
		for i := range entries {
			encode(i)
		}
	}
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return frames, nil
}
