// 保存済み監査のスレッド範囲と列検証を、新しい照会を書かずに検査する。
package disclosure

import (
	"oimobbs/internal/domain"
	"testing"
)

func TestHTTPQueryAuditScope(t *testing.T) {
	for _, thread := range []uint64{0, 123} {
		a := Audit{Action: "http_query"}
		a.Case.Scope.Thread = domain.U64(thread)
		err := validateHTTPQueryAudit(a)
		if (err != nil) != (thread != 0) {
			t.Fatal(thread, err)
		}
	}
}

// TestRetiredAuditWritesRejected は読み取り用の監査形式を新規書き込みへ流用できないことを検査する。
func TestRetiredAuditWritesRejected(t *testing.T) {
	s, _, input, actor, now, _ := fixture(t)
	c, err := s.Create(input, actor, `"evidence:new"`, "current-create", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"query", "http_query", "rejected_query", "transfer"} {
		if _, err = s.append(c, actor, action, "retired", nil, c.ETag(), "retired-"+action, nil, now); err != ErrInvalid {
			t.Fatal(action, err)
		}
	}
	current, err := s.Get(c.ID)
	if err != nil || current.ETag() != c.ETag() {
		t.Fatal("retired action changed signed history", err)
	}
}
