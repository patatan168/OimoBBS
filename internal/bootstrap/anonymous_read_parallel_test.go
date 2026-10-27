// 通常Cookieの確認が既存のサイト読取りを排他せず、発行や期限更新だけを保存列へ渡すことを確認する。
package bootstrap

import (
	"net/netip"
	"testing"
	"time"
)

func TestAnonymousReadDoesNotWaitForOtherSiteReaders(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "valid"}[enabled], func(t *testing.T) {
			var repo *Repository
			if enabled {
				_, repo, _, _ = anonymousFixture(t, "required")
			} else {
				_, repo = adminFixture(t)
			}
			defer repo.Close()
			raw := ""
			ip := netip.MustParseAddr("192.0.2.1")
			if enabled {
				cookie, err := repo.anonymousCookie("", ip, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				raw = cookie.Value
			}
			repo.mu.RLock()
			done := make(chan error, 1)
			go func() {
				cookie, err := repo.anonymousCookie(raw, ip, time.Now)
				if cookie != nil {
					done <- ErrPostingUnavailable
					return
				}
				done <- err
			}()
			select {
			case err := <-done:
				repo.mu.RUnlock()
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				repo.mu.RUnlock()
				<-done
				t.Fatal("cookie check queued a site writer")
			}
		})
	}
}
