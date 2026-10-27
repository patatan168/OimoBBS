// 全体128枠のうち投稿120件を保持し、保守の共通ロック待ちが閲覧8件と後続503へ連鎖することを再現する。
package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"oimobbs/internal/waf"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPeriodicMaintenanceAvoidsTrafficCascade(t *testing.T) {
	for _, idle := range []bool{false, true} {
		t.Run(fmt.Sprint("periodic_idle=", idle), func(t *testing.T) {
			_, r := adminFixture(t)
			defer r.Close()
			info, err := r.CreateBoard(t.Context(), "trafficmaintenance", "保守と受付")
			if err != nil {
				t.Fatal(err)
			}
			if err = r.EnableControlExpiry(t.Context()); err != nil {
				t.Fatal(err)
			}
			policy := WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()}
			policy.Traffic.Posting.GlobalConcurrent = 128
			r.publishWAF(policy)
			for i := 1; i <= 120; i++ {
				release, d := r.publicTraffic.AcquireOperation(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), waf.Posting, time.Now())
				if d.Status != 0 {
					t.Fatal("posting fixture refused", i, d)
				}
				defer release()
			}
			b := r.posting[info.ID]
			started, release, ownerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				defer close(ownerDone)
				_, _ = b.worker.Submit(context.Background(), func() (any, error) { close(started); <-release; return nil, nil })
			}()
			<-started
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }); <-ownerDone }
			defer unblock()
			maintained := make(chan error, 1)
			go func() { _, e := r.sweepExpiredControlMode(t.Context(), 128, time.Now, idle); maintained <- e }()
			if idle {
				select {
				case err = <-maintained:
				case <-time.After(time.Second):
					t.Fatal("periodic expiry did not defer")
				}
				if err != nil {
					t.Fatal(err)
				}
			} else {
				// 明示経路は旧周期と同じ待機動作。保守が共通排他を取ったことを同期する。
				deadline := time.Now().Add(time.Second)
				for {
					if !r.mu.TryRLock() {
						break
					}
					r.mu.RUnlock()
					if time.Now().After(deadline) {
						t.Fatal("legacy maintenance did not acquire site lock")
					}
					runtime.Gosched()
				}
			}
			entered := make(chan struct{}, 16)
			handler := r.trafficHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				entered <- struct{}{}
				if _, e := r.postingOwner(info.ID); e != nil {
					w.WriteHeader(503)
					return
				}
				w.WriteHeader(204)
			}), false)
			request := func(n int) int {
				req := httptest.NewRequest("GET", "/trafficmaintenance/subject.txt", nil)
				req.RemoteAddr = fmt.Sprintf("198.51.100.%d:12345", n)
				out := httptest.NewRecorder()
				handler.ServeHTTP(out, req)
				return out.Code
			}
			readDone := make(chan int, 8)
			for i := 1; i <= 8; i++ {
				go func(n int) { readDone <- request(n) }(i)
			}
			for range 8 {
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("reader did not reach metadata lookup")
				}
			}
			if idle {
				for range 8 {
					select {
					case status := <-readDone:
						if status != 204 {
							t.Fatal(status)
						}
					case <-time.After(time.Second):
						t.Fatal("reader waited for posting owner")
					}
				}
			} else if active := r.publicTraffic.Stats().Active; active != 128 {
				t.Fatal("cascade was not reproduced", active)
			}
			want := 503
			if idle {
				want = 204
			}
			activeBefore := r.publicTraffic.Stats().Active
			got := request(9)
			t.Logf("periodic_idle=%t global_limit=128 posting_active=120 active_before_ninth=%d ninth_status=%d", idle, activeBefore, got)
			if got != want {
				t.Fatal("ninth request", got, want)
			}
			unblock()
			if !idle {
				if err = <-maintained; err != nil {
					t.Fatal(err)
				}
				for range 8 {
					if status := <-readDone; status != 204 {
						t.Fatal(status)
					}
				}
				if stats := r.publicTraffic.Stats(); stats.Overloaded != 1 {
					t.Fatal("global concurrency rejection missing", stats)
				}
			} else if stats := r.publicTraffic.Stats(); stats.Overloaded != 0 {
				t.Fatal("periodic maintenance caused overload", stats)
			}
		})
	}
}
