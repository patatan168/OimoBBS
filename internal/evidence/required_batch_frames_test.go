// 並行署名・符号化が既存の署名連鎖と正規frameをbyte単位で維持することを検査する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"reflect"
	"runtime"
	"testing"
)

func TestRequiredParallelFrameBytesAndSignatures(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	owner := domain.NewID()
	j := &Journal{owner: owner, day: 20261023, key: key, keyID: 10}
	var entries []Entry
	var requests []AppendRequest
	var want []Event
	var prev domain.Hash
	for i := 0; i < 64; i++ {
		src := Source{owner, j.day, uint64(i + 1)}
		id := domain.NewID()
		payload, err := json.Marshal(testPayload{owner, domain.U64(j.day), domain.U64(i + 1), "payload"})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := Seal(src, id, "attempt", payload, prev, j.keyID, key)
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := prepareSeal(src, id, "attempt", payload, prev, j.keyID, key)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, Entry{unsigned, payload})
		requests = append(requests, AppendRequest{ID: id, Kind: "attempt", Committed: 1})
		want = append(want, signed)
		prev = signed.EventSHA
	}
	serial := append([]Entry(nil), entries...)
	a, err := j.prepareBatchFrames(serial, requests, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := j.prepareBatchFrames(entries, requests, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range entries {
		raw, _, err := referenceJournalJSON(want[i], uint64(i+1), requests[i].Committed, false)
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := store.EncodeFrame(store.Frame{FirstSeq: uint64(i + 1), Records: []store.Record{{ID: requests[i].ID, JSON: raw}}})
		if err != nil || !bytes.Equal(a[i], legacy) {
			t.Fatal("legacy frame changed", i, err)
		}
		if !bytes.Equal(a[i], b[i]) || !reflect.DeepEqual(entries[i].Event, want[i]) {
			t.Fatal("parallel output changed", i)
		}
		if _, err := Verify(Source{owner, j.day, uint64(i + 1)}, entries[i].Event, entries[i].Event.PreviousSHA, j.keyID, key.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
}
