// 固定journal符号化を汎用JSONと差分照合し、署名対象と保存byteの一致を検査する。
package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
)

// referenceJournalJSON は従来の二段階Marshalを比較用に残す。
func referenceJournalJSON(event Event, seq uint64, committed domain.Time, optional bool) ([]byte, int, error) {
	value, err := json.Marshal(event)
	if err != nil {
		return nil, 0, err
	}
	result := store.ControlResult{Code: "evidence_saved", Targets: []string{event.RecordID.String()}}
	if optional {
		result = store.ControlResult{Code: "saved", Targets: []string{}}
	}
	op := store.ControlOperation{Schema: 1, Seq: domain.U64(seq), Committed: committed, ExpectedSeq: domain.U64(seq - 1), Actor: domain.Actor{Kind: "system", Reason: "evidence"}, Mutations: []store.Mutation{{Collection: event.Kind, Key: event.RecordID.String(), Value: value}}, Result: result}
	raw, err := json.Marshal(op)
	return raw, len(value), err
}

func checkJournalJSON(t *testing.T, payload, signature []byte, seq uint64, committed int64, kind string) {
	t.Helper()
	event := Event{Schema: "evidence-v1", RecordID: domain.ID{1, 2, 3}, Kind: kind, Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature), PayloadSHA: domain.Hash{9}, EventSHA: domain.Hash{8}, PreviousSHA: domain.Hash{7}, SigningKeyID: ^uint32(0)}
	for _, optional := range []bool{false, true} {
		want, wn, we := referenceJournalJSON(event, seq, domain.Time(committed), optional)
		got, gn, ge := marshalJournalOperation(event, payload, signature, seq, domain.Time(committed), optional)
		if we != nil || ge != nil || wn != gn || !bytes.Equal(want, got) {
			t.Fatalf("byte mismatch optional=%t sizes=%d/%d errors=%v/%v\nwant %s\ngot %s", optional, wn, gn, we, ge, want, got)
		}
	}
}

func TestJournalJSONBytes(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 1023, 8192, 512 << 10} {
		payload := bytes.Repeat([]byte{0, 255, '<', '\\', '\n'}, size/5+1)[:size]
		for _, seq := range []uint64{1, 42, ^uint64(0)} {
			checkJournalJSON(t, payload, payload[:min(size, 64)], seq, -1<<63, "evidence_proposal")
		}
	}
	checkJournalJSON(t, []byte("日本語😀"), []byte{1, 255}, 0, 1<<63-1, "escape<>&\"\\\n\u2028")
}

func FuzzJournalJSONBytes(f *testing.F) {
	f.Add([]byte("日本語\n"), []byte{1, 255}, uint64(1), int64(1), "attempt")
	f.Fuzz(func(t *testing.T, payload, signature []byte, seq uint64, committed int64, kind string) {
		if len(payload)+len(signature)+len(kind) > 512<<10 {
			t.Skip()
		}
		checkJournalJSON(t, payload, signature, seq, committed, kind)
	})
}

func BenchmarkJournalJSON(b *testing.B) {
	payload := bytes.Repeat([]byte("posting-payload"), 400)
	signature := bytes.Repeat([]byte{7}, 64)
	event := Event{Schema: "evidence-v1", RecordID: domain.ID{1}, Kind: "evidence_proposal", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature), SigningKeyID: 1}
	for _, fast := range []bool{false, true} {
		name := "standard"
		if fast {
			name = "fixed"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var err error
				if fast {
					_, _, err = marshalJournalOperation(event, payload, signature, 42, 1, false)
				} else {
					_, _, err = referenceJournalJSON(event, 42, 1, false)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
