// OS標準DNSの旧保存値と明示値を同じ方式として扱い、確認済み結果を維持する。
package identity

import (
	"net/netip"
	"testing"
	"time"
)

// TestDNSModeEquivalentSettingsKeepConfirmation は同じDNS方式の保存で確認結果を失わない。
func TestDNSModeEquivalentSettingsKeepConfirmation(t *testing.T) {
	for _, pair := range [][2]string{{"", "system"}, {"system", ""}, {"", ""}, {"system", "system"}, {"google_https", "google_https"}} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) {
			cache := NewHostCache(nil)
			defer cache.Close()
			cache.mode = pair[0]
			ip := netip.MustParseAddr("192.0.2.1")
			// 照会は行わず、取得済みの結果が保存時に維持される契約だけを検査する。
			cache.entries[ip] = cache.order.PushFront(hostEntry{ip: ip, reverse: true, status: HostDNSConfirmed, expires: time.Now().Add(time.Hour)})
			cache.ConfigureDNS(pair[1])
			if !cache.ReverseResolved(ip) || cache.DNSStatus(ip) != HostDNSConfirmed {
				t.Fatal("equivalent setting discarded confirmed DNS", pair)
			}
		})
	}
}
