// 初回予約Sync直後の取消と元解除後の参照未保存を、署名履歴から安全に回復する。
package disclosure

import (
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestRequiredTerminalReservationReconciliation(t *testing.T) {
	for _, releasedFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "released"}[releasedFirst], func(t *testing.T) {
			s, h, _, key, c, actor, receipt, _, now, _ := requiredReservationPreparedFixture(t)
			c, e := s.Release(c.ID, actor, c.ETag(), "cancel-unbound", "取消", now)
			if e != nil {
				t.Fatal(e)
			}
			if releasedFirst {
				if _, e = h.Release(receipt, domain.Time(now.UnixNano())); e != nil {
					t.Fatal(e)
				}
			}
			original, found, e := h.OriginalReceipt(c.ID)
			if e != nil || !found || !sameRequiredReceipt(original, receipt) {
				t.Fatal("original reservation lost", e)
			}
			c, e = s.ReconcileRequiredReservation(c.ID, actor, c.ETag(), original, now)
			if e != nil || c.Required == nil || c.State != "closed" {
				t.Fatal(c, e)
			}
			current, _, e := h.Receipt(c.ID)
			if e != nil {
				t.Fatal(e)
			}
			current, e = h.Release(current, domain.Time(now.UnixNano()))
			if e != nil {
				t.Fatal(e)
			}
			c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), current, now)
			if e != nil || c.Required.Released == nil {
				t.Fatal(c, e)
			}
			before := c.ETag()
			c, e = s.ReconcileRequiredReservation(c.ID, actor, c.ETag(), original, now.Add(time.Nanosecond))
			if e != nil || c.ETag() != before {
				t.Fatal("reconciliation was not idempotent", e)
			}
			rows, sources := inspectedRequiredFixture(t, s, key, c)
			if e = CheckRequiredCaseReservations(rows, sources); e != nil {
				t.Fatal("reconciled history invalid", e)
			}
		})
	}
}
