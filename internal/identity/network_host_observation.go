// 期限内のDNS回答と正引き確認を、分類とは独立した観測値として提供する。
package identity

import (
	"net/netip"
	"time"
)

// HostObservation は照会完了時点のPTR名・正引き確認・取得方式。名前は小文字・末尾ドットなし。
// Statusがconfirmedの場合だけConfirmedNameの正引きが照会元IPと一致する。本人や所属は保証しない。
type HostObservation struct {
	Names         []string
	ConfirmedName string
	Status        HostDNSStatus
	ObservedAt    time.Time
	Resolver      string
}

// Observation は有効なキャッシュをコピーする。未照会・処理中・期限切れではfalseを返し、DNS通信は行わない。
func (c *HostCache) Observation(ip netip.Addr) (HostObservation, bool) {
	v, ok := c.cached(ip)
	if !ok {
		return HostObservation{}, false
	}
	names := append([]string{}, v.names...)
	return HostObservation{Names: names, ConfirmedName: v.hostname, Status: v.status, ObservedAt: v.observed, Resolver: v.resolver}, true
}
