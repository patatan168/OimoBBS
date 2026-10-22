// 廃止した投稿資格列の指定で提出物を作らないことを確認する。
package disclosure

import (
	"oimobbs/internal/app"
	"testing"
)

func TestPrincipalExportRejected(t *testing.T) {
	s, _, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "principal-create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "principal-hold", "保全", []app.AcceptedEvidence{record}, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Generate(c.ID, actor, c.ETag(), "principal-export", "提出", []string{"principal"}, now); e != ErrInvalid {
		t.Fatal("removed column accepted", e)
	}
}
