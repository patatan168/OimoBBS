// 廃止した投稿資格列や未知の列を、内部APIでも読み替えず拒否する。
package app

import "testing"

func TestAcceptedEvidenceRejectsRemovedColumns(t *testing.T) {
	r, _ := acceptedContentFixture(t)
	for _, columns := range [][]string{{"principal"}, {"unknown"}, {"content", "content"}} {
		if _, e := r.Project(columns); e != ErrEvidenceGap {
			t.Fatal("invalid selection accepted", columns, e)
		}
	}
}
