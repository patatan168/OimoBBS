// 投稿列を意図的に停止し、周期保守がサイト共通排他で閲覧を巻き込まないことを検査する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"sync"
	"testing"
	"time"
)

func TestPeriodicControlMaintenanceDefersBusyBoard(t *testing.T) {
	for _, kind := range []string{"expiry", "audit", "checkpoint", "carry", "retention"} {
		t.Run(kind, func(t *testing.T) {
			_, r := adminFixture(t)
			defer r.Close()
			info, err := r.CreateBoard(t.Context(), "busymaintenance", "保守待機")
			if err != nil {
				t.Fatal(err)
			}
			if err = r.EnableControlExpiry(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = r.TransferThreadAudits(t.Context(), 1); err != nil {
				t.Fatal(err)
			}
			b := r.posting[info.ID]
			if kind == "expiry" {
				old := domain.Time(time.Now().Add(-25 * time.Hour).UnixNano())
				seedExpiredAdminReceipt(t, r, old, 1)
				value, e := b.worker.Submit(t.Context(), func() (any, error) { return b.adminBoard() })
				if e != nil {
					t.Fatal(e)
				}
				receipt := adminBoardReceipt{ID: domain.NewID(), Admin: domain.NewID(), Key: domain.Hash{5}, Request: domain.Hash{6}, Result: value.(AdminBoard), Created: old, Expires: old + 86400e9}
				if _, e = b.worker.Submit(t.Context(), func() (any, error) {
					return nil, appendControlAt(b.control, old, "receipt_fixture", []store.Mutation{mutation("admin_receipt", receipt.Key.String(), receipt, nil)})
				}); e != nil {
					t.Fatal(e)
				}
			}
			started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }); <-finished }
			defer unblock()
			go func() {
				defer close(finished)
				_, _ = b.worker.Submit(context.Background(), func() (any, error) { close(started); <-release; return nil, nil })
			}()
			<-started
			done := make(chan error, 1)
			go func() {
				if kind == "checkpoint" || kind == "carry" || kind == "retention" {
					if kind == "retention" {
						r.optionalHoldLifecycleMu.Lock()
						defer r.optionalHoldLifecycleMu.Unlock()
					}
					r.mu.Lock()
					var e error
					if kind == "retention" {
						e = r.reconcileRequiredRetentionLocked(t.Context())
					} else if kind == "checkpoint" {
						e = r.sweepRequiredCheckpointLocked(t.Context())
					} else {
						e = r.sweepBodyCarryRetirementsLocked(t.Context())
					}
					r.mu.Unlock()
					done <- e
					return
				}
				if kind == "audit" {
					done <- r.maintainThreadAudits(t.Context())
					return
				}
				report, e := r.sweepExpiredControlMode(t.Context(), 128, time.Now, true)
				if e == nil && (!report.More || report.Boards != 0) {
					e = errors.New("busy board not reported as deferred")
				}
				done <- e
			}()
			select {
			case err = <-done:
			case <-time.After(time.Second):
				unblock()
				<-done
				t.Fatal("periodic maintenance waited for a busy posting board")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = r.postingOwner(info.ID); err != nil {
				t.Fatal("public lookup blocked or unavailable", err)
			}
			unblock()
			// 空いた後の通常実行を拒否せず、保守を恒久的に無効化しない。
			if kind == "checkpoint" || kind == "carry" || kind == "retention" {
				if kind == "retention" {
					r.optionalHoldLifecycleMu.Lock()
				}
				r.mu.Lock()
				if kind == "retention" {
					err = r.reconcileRequiredRetentionLocked(t.Context())
				} else if kind == "checkpoint" {
					err = r.sweepRequiredCheckpointLocked(t.Context())
				} else {
					err = r.sweepBodyCarryRetirementsLocked(t.Context())
				}
				r.mu.Unlock()
				if kind == "retention" {
					r.optionalHoldLifecycleMu.Unlock()
				}
			} else if kind == "audit" {
				err = r.maintainThreadAudits(t.Context())
			} else {
				var report ControlExpiryReport
				report, err = r.sweepExpiredControlMode(t.Context(), 128, time.Now, true)
				if err == nil && (report.Boards != 1 || report.More) {
					t.Fatal("deferred expiry was not completed", report)
				}
			}
			if err != nil {
				t.Fatal("idle maintenance failed", err)
			}
		})
	}
}
