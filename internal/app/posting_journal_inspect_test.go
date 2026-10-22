// 原本journalの読取り検査で署名/所有者/seqを照合し、原本や回収intentを変更しない。
package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPostingJournalReadOnlyInspection(t *testing.T) {
	f := newRetirementFixture(t)
	before := retirementFiles(t, f.path)
	v, e := evidence.InspectJournal(f.path, f.owner, 20231114, 10, f.key, PostingValidator(fixtureCapture))
	if e != nil || v.Sequence != 2 || v.RequiredRetirements != 0 || v.RequiredFloor != 0 {
		t.Fatal(v, e)
	}
	_, wrongKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name     string
		owner    domain.ID
		day      uint64
		keyID    uint32
		key      ed25519.PrivateKey
		validate evidence.PayloadValidator
	}{
		{"owner", domain.NewID(), 20231114, 10, f.key, PostingValidator(fixtureCapture)},
		{"day", f.owner, 20231115, 10, f.key, PostingValidator(fixtureCapture)},
		{"key_id", f.owner, 20231114, 11, f.key, PostingValidator(fixtureCapture)},
		{"signature", f.owner, 20231114, 10, wrongKey, PostingValidator(fixtureCapture)},
		{"validator", f.owner, 20231114, 10, f.key, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := evidence.InspectJournal(f.path, tc.owner, tc.day, tc.keyID, tc.key, tc.validate); e == nil {
				t.Fatal("invalid source inspected")
			}
		})
	}
	if !reflect.DeepEqual(before, retirementFiles(t, f.path)) {
		t.Fatal("read-only inspection changed source files")
	}
	missing := filepath.Join(f.path, "absent")
	if _, e = evidence.InspectJournal(missing, f.owner, 20231114, 10, f.key, PostingValidator(fixtureCapture)); !os.IsNotExist(e) {
		t.Fatal("missing source", e)
	}
	if _, e = os.Lstat(missing); !os.IsNotExist(e) {
		t.Fatal("inspection created source", e)
	}
}
