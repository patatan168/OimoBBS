// 最新の取消署名も原本回収の時計床に含め、読取りで案件を更新しないことを確認する。
package disclosure

import (
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestRequiredGCClockFloorIncludesLaterCancellation(t *testing.T) {
	s, _, _, c, actor, now, _ := requiredExtensionFixture(t)
	late := now.Add(time.Minute)
	if _, e := s.Release(c.ID, actor, c.ETag(), "floor-cancel", "取消", late); e != nil {
		t.Fatal(e)
	}
	before, e := s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	floor, e := s.RequiredGCClockFloor()
	if e != nil || floor != domain.Time(late.UnixNano()) {
		t.Fatal("latest audit omitted from clock floor", floor, e)
	}
	after, e := s.Get(c.ID)
	if e != nil || before.ETag() != after.ETag() {
		t.Fatal("clock inspection changed case", e)
	}
}
