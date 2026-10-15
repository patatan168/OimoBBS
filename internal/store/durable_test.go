// Sync失敗と不完全末尾を、実際の書込境界で試験する。
package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"oimobbs/internal/domain"
	"testing"
)

type faultWriter struct {
	bytes.Buffer
	syncErr  error
	writeErr error
	short    bool
	writes   int
}

func (w *faultWriter) Write(b []byte) (int, error) {
	w.writes++
	if w.short {
		return len(b) / 2, nil
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.Buffer.Write(b)
}
func (w *faultWriter) Sync() error { return w.syncErr }
func TestCommitFault(t *testing.T) {
	f, _ := EncodeFrame(Frame{1, []Record{{domain.NewID(), []byte(`{"x":1}`), nil}}})
	for _, w := range []*faultWriter{{syncErr: errors.New("sync")}, {writeErr: errors.New("write")}, {short: true}} {
		writer := NewWriter(w)
		if r := writer.Commit(f); r.Status != Unknown {
			t.Fatal(r)
		}
		if r := writer.Commit(f); r.Status != Unknown || w.writes != 1 {
			t.Fatal("writer resumed")
		}
	}
	w := &faultWriter{}
	if r := NewWriter(w).Commit(f); r.Status != Durable {
		t.Fatal(r)
	}
}
func TestRequiredPrefixAndTruncation(t *testing.T) {
	h := Header{Owner: domain.NewID(), Key: 1, Generation: 1}
	hb, _ := EncodeHeader(h)
	f, _ := EncodeFrame(Frame{1, []Record{{domain.NewID(), []byte(`{"a":1}`), nil}}})
	first := append(hb, f...)
	d := Delta{RequiredSeq: 1, RequiredEnd: domain.U64(len(first)), RequiredSHA: sha256.Sum256(first)}
	g, _ := EncodeFrame(Frame{2, []Record{{domain.NewID(), []byte(`{"a":2}`), nil}}})
	for cut := 0; cut < len(g); cut++ {
		all := append(bytes.Clone(first), g[:cut]...)
		end, partial, e := Scan(bytes.NewReader(all), h, d, nil)
		if e != nil || end != int64(len(first)) || partial != (cut > 0) {
			t.Fatalf("cut %d end %d partial %v: %v", cut, end, partial, e)
		}
	}
	for cut := 0; cut < len(first); cut++ {
		if _, _, e := Scan(bytes.NewReader(first[:cut]), h, d, nil); e == nil {
			t.Fatalf("required cut %d accepted", cut)
		}
	}
	all := append(bytes.Clone(first), g...)
	all[len(all)-1] ^= 1
	if _, _, e := Scan(bytes.NewReader(all), h, d, nil); !errors.Is(e, ErrCorrupt) {
		t.Fatal(e)
	}
}
func TestCurrentRawHash(t *testing.T) {
	m := Manifest{Schema: 1, BoardID: domain.NewID(), ThreadKey: 1, Generation: 1, Delta: Delta{File: "delta-000001.wal", RequiredSeq: 1, RequiredEnd: 100}}
	b, e := EncodeCurrent(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeCurrent(b); e != nil {
		t.Fatal(e)
	}
	bad := bytes.Replace(b, []byte(`"schema":1`), []byte(`"schema": 1`), 1)
	if _, e = DecodeCurrent(bad); e == nil {
		t.Fatal("reformatted manifest accepted")
	}
}
