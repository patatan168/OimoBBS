// 固定案内の変更をHTTPキャッシュと公開送信リースへ反映することを検査する。
package app

import (
	"oimobbs/internal/domain"
	"testing"
)

func TestSystemThreadSnapshot(t *testing.T) {
	first := NewSystemThreadSnapshot("受付", []byte("first"))
	same := NewSystemThreadSnapshot("受付", []byte("first"))
	changed := NewSystemThreadSnapshot("受付", []byte("changed"))
	if first.Revision != same.Revision || first.Revision == changed.Revision {
		t.Fatal("instruction cache revision")
	}
	lease, err := first.AcquirePublic(domain.Time(1), func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err = lease.Check(domain.Time(2)); err != nil {
		t.Fatal(err)
	}
	if first.PostCount != 1 || !first.CanReply {
		t.Fatal("fixed receipt")
	}
}
