// 新しい照会操作の先行署名・reader境界と、推定スレッドscopeの拒否を検査する。
package disclosure

import "testing"

func TestHTTPQueryAuditReaderAndThreadScope(t *testing.T) {
	s, key, input, actor, now, _ := fixture(t)
	input.Scope.Thread = 0
	c, e := s.Create(input, actor, `"evidence:new"`, "http-case", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordHTTPQuery(c.ID, actor, c.ETag(), "http-query", "受付前拒否の確認", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = InspectVersion(s.root, key, 55); e == nil {
		t.Fatal("reader55 accepted HTTP query action")
	}
	if e = InspectVersion(s.root, key, 56); e != nil {
		t.Fatal(e)
	}
	input.Scope.Thread = 123
	other, e := s.Create(input, actor, `"evidence:new"`, "thread-case", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RecordHTTPQuery(other.ID, actor, other.ETag(), "thread-query", "照会", nil, now); e != ErrInvalid {
		t.Fatal("thread scope broadened", e)
	}
}
