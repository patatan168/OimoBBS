// サービス固有のDNS名を正引き確認し、板ワーカー外で有界に分類を補完する。
package identity

import (
	"container/list"
	"context"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// HostResolver は逆引き・正引きだけを提供する。OS標準DNSまたは固定のHTTPS DNS取得先を使用する。
type HostResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// HostRule はサービス固有のホスト名と表示の対応。ASN全体の固定/携帯分類には使わない。
type HostRule struct{ Pattern, Kind, Label, Suffix, Description, Provider string }

// hostRules は携帯・公衆Wi-Fi・固定アクセスの既知名前空間に限定する。
var hostRules = []HostRule{
	{`^[a-z0-9.-]+\.ftth\.ucom\.ne\.jp$`, "fixed", "ﾜｯﾁｮｲ", "0", "UCOM / アルテリア FTTH", "arteria"},
	{`^p[0-9]+-ipngn[0-9]+\.[a-z0-9.-]+\.ocn\.ne\.jp$`, "fixed", "ﾜｯﾁｮｲ", "0", "OCN 光ネクスト", "ocn"},
	{`^[a-z0-9.-]+\.ppp-bb\.dion\.ne\.jp$`, "fixed", "ﾜｯﾁｮｲ", "0", "au one net ブロードバンド", "kddi"},
	{`^[a-z0-9.-]+\.ap\.so-net\.ne\.jp$`, "fixed", "ﾜｯﾁｮｲ", "0", "So-net 固定アクセス", "sonet"},
	{`^[a-z0-9.-]+\.ap\.nuro\.jp$`, "fixed", "ﾜｯﾁｮｲ", "0", "NURO 光", "sonet"},
	{`^[a-z0-9.-]+\.wi-fi\.wi2\.ne\.jp$`, "wifi", "ﾜｲﾜｲ", "F", "Wi2", ""},
	{`^[a-z0-9.-]+\.m-zone\.jp$`, "wifi", "ｴﾑｿﾞﾈ", "F", "docomo Wi-Fi", ""},
	{`^p[0-9]+-omed[0-9]+\.[a-z0-9-]+\.ocn\.ne\.jp$`, "mvno", "ﾜﾝﾄﾝｷﾝ", "M", "OCNモバイルONE", ""},
	{`^[a-z0-9.-]+\.vmobile\.jp$`, "mvno", "ﾌﾞｰｲﾓ", "M", "IIJmio系", ""},
	{`^[a-z0-9.-]+\.mineo\.jp$`, "mvno", "ｵｲｺﾗﾐﾈｵ", "M", "mineo", ""},
	{`^[a-z0-9.-]+\.bmobile\.ne\.jp$`, "mvno", "ﾍﾞｰｲﾓ", "M", "b-mobile系", ""},
	{`^[a-z0-9.-]+\.spmode\.ne\.jp$`, "mobile", "ｽﾌﾟｯｯ", "d", "ドコモ spモード", ""},
	{`^[a-z0-9.-]+\.mopera\.net$`, "mobile", "ﾍﾟﾗﾍﾟﾗ", "D", "ドコモ mopera", ""},
	{`^[a-z0-9.-]+\.au-net\.ne\.jp$`, "mobile", "ｱｳｱｳ", "a", "au", ""},
	{`^[a-z0-9.-]+\.panda-world\.ne\.jp$`, "mobile", "ｻｻｸｯﾃﾛ", "p", "SoftBank iPhone系", ""},
	{`^[a-z0-9.-]+\.openmobile\.ne\.jp$`, "mobile", "ｵｯﾍﾟｹ", "r", "SoftBank / Y!mobile系", ""},
	{`^[a-z0-9.-]+\.access-internet\.ne\.jp$`, "mobile", "ｱ-ｸｾ-", "x", "SoftBank データ通信系", ""},
}

// ServiceHostRules は管理画面向けに対応表のコピーを返す。
func ServiceHostRules() []HostRule { return append([]HostRule(nil), hostRules...) }

var hostPatterns = func() []*regexp.Regexp {
	r := make([]*regexp.Regexp, len(hostRules))
	for i, v := range hostRules {
		r[i] = regexp.MustCompile(v.Pattern)
	}
	return r
}()

type hostEntry struct {
	ip       netip.Addr
	class    NetworkClass
	hostname string
	reverse  bool
	expires  time.Time
}
type hostFlight struct {
	done       chan struct{}
	generation uint64
	resolver   HostResolver
}

// HostCache は1024 IP/同時4照会/計64処理を保持する。肯定10分・否定30秒、DNS全体1秒。
// Matchは外部通信をしない。Resolveを所有ワーカーの外から呼んで候補を準備する。
type HostCache struct {
	mu         sync.Mutex
	resolver   HostResolver
	mode       string
	generation uint64
	clock      func() time.Time
	entries    map[netip.Addr]*list.Element
	order      list.List
	flights    map[netip.Addr]*hostFlight
	workers    chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	closed     bool
}

// NewHostCache は外部照会を要求されるまで開始しない。停止時はCloseが必要。
func NewHostCache(resolver HostResolver) *HostCache {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &HostCache{resolver: resolver, clock: time.Now, entries: make(map[netip.Addr]*list.Element), flights: make(map[netip.Addr]*hostFlight), workers: make(chan struct{}, 4), ctx: ctx, cancel: cancel}
}

// Resolve は同じIPの照会を共有する。呼出元の取消は共有照会を取り消さない。
// 混雑/不明/失敗は空候補へ戻し、携帯回線と断定しない。
func (c *HostCache) Resolve(ctx context.Context, ip netip.Addr) {
	ip = ip.Unmap()
	if c == nil || !hostEligible(ip) || ctx.Err() != nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if entry := c.entries[ip]; entry != nil && c.clock().Before(entry.Value.(hostEntry).expires) {
		c.order.MoveToFront(entry)
		c.mu.Unlock()
		return
	}
	flight := c.flights[ip]
	if flight != nil && flight.generation != c.generation {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-flight.done:
			c.Resolve(ctx, ip)
			return
		}
	}
	if flight == nil {
		if len(c.flights) >= 64 {
			c.mu.Unlock()
			return
		}
		flight = &hostFlight{done: make(chan struct{}), generation: c.generation, resolver: c.resolver}
		c.flights[ip] = flight
		c.wg.Add(1)
		go c.lookup(ip, flight)
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-flight.done:
	}
}

// Match は有効な肯定候補だけを返す。期限切れは再確認まで分類に使わない。
func (c *HostCache) Match(ip netip.Addr) (NetworkClass, bool) {
	value, ok := c.cached(ip)
	return value.class, ok && value.class.CIDR != ""
}

// Hostname は管理用の確認済み逆引き名だけを返す。否定結果は公開しない。
func (c *HostCache) Hostname(ip netip.Addr) string {
	value, ok := c.cached(ip)
	if ok {
		return value.hostname
	}
	return ""
}
func (c *HostCache) cached(ip netip.Addr) (hostEntry, bool) {
	if c == nil {
		return hostEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[ip.Unmap()]
	if entry == nil || c.closed {
		return hostEntry{}, false
	}
	value := entry.Value.(hostEntry)
	if !c.clock().Before(value.expires) {
		return hostEntry{}, false
	}
	c.order.MoveToFront(entry)
	return value, true
}

// lookup は待機を含め1秒に制限し、逆引き名の正引きが元IPを含む場合だけ採用する。
func (c *HostCache) lookup(ip netip.Addr, flight *hostFlight) {
	defer c.wg.Done()
	ctx, cancel := context.WithTimeout(c.ctx, time.Second)
	defer cancel()
	var class NetworkClass
	hostname := ""
	reverse := false
	select {
	case c.workers <- struct{}{}:
		class, hostname, reverse = verifyHost(ctx, flight.resolver, ip)
		<-c.workers
	case <-ctx.Done():
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.flights, ip)
	if !c.closed && flight.generation == c.generation {
		ttl := 30 * time.Second
		if hostname != "" {
			ttl = 10 * time.Minute
		}
		if old := c.entries[ip]; old != nil {
			c.order.Remove(old)
			delete(c.entries, ip)
		}
		for c.order.Len() >= 1024 {
			old := c.order.Back()
			delete(c.entries, old.Value.(hostEntry).ip)
			c.order.Remove(old)
		}
		c.entries[ip] = c.order.PushFront(hostEntry{ip: ip, class: class, hostname: hostname, reverse: reverse, expires: c.clock().Add(ttl)})
	}
	close(flight.done)
}

// verifyHost は一般のPTR名も正引きで元IPとの一致を確認する。分類は既知サービスだけに限定する。
func verifyHost(ctx context.Context, resolver HostResolver, ip netip.Addr) (NetworkClass, string, bool) {
	names, err := resolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) > 16 {
		return NetworkClass{}, "", false
	}
	reverse := false
	confirmed := ""
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSuffix(raw, "."))
		if !validDNSHostname(name) {
			continue
		}
		reverse = true
		ips, err := resolver.LookupNetIP(ctx, "ip", name)
		if err != nil || len(ips) > 32 {
			continue
		}
		verified := false
		for _, forward := range ips {
			if forward.Unmap() == ip {
				verified = true
				break
			}
		}
		if !verified {
			continue
		}
		if confirmed == "" {
			confirmed = name
		}
		for i, pattern := range hostPatterns {
			if pattern.MatchString(name) {
				rule := hostRules[i]
				return NetworkClass{CIDR: netip.PrefixFrom(ip, ip.BitLen()).String(), Kind: rule.Kind, Label: rule.Label, Suffix: rule.Suffix, Provider: hostRuleProvider(rule)}, name, true
			}
		}
	}
	return NetworkClass{}, confirmed, reverse
}

// hostEligible は公開ユニキャストだけを許可し、内部/予約/検証用範囲のDNS照会を避ける。
func hostEligible(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range reservedHostPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

var reservedHostPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("240.0.0.0/4")}

// Close は新規照会を止め、待機・DNSを取消し、すべての照会goroutineを回収する。
func (c *HostCache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	if closer, ok := c.resolver.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	c.mu.Unlock()
	c.wg.Wait()
}

// ReverseResolved は有効なPTR名の取得成功を返す。サービス分類や正引き一致とは独立する。
func (c *HostCache) ReverseResolved(ip netip.Addr) bool {
	value, ok := c.cached(ip)
	return ok && value.reverse
}

// ConfigureDNS は保存済みの取得方式を反映し、旧方式のキャッシュと進行中結果を無効化する。
func (c *HostCache) ConfigureDNS(mode string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.mode == mode {
		return
	}
	if closer, ok := c.resolver.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	c.mode = mode
	c.generation++
	c.entries = make(map[netip.Addr]*list.Element)
	c.order.Init()
	c.resolver = net.DefaultResolver
	if mode == "google_https" {
		c.resolver = NewGoogleHTTPSResolver()
	}
}

// validDNSHostname はPTRの名前をDNSラベルの構文と長さで検査する。
func validDNSHostname(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

// hostProvider は確認済みサービスを安定した運営分類キーへ対応させる。
func hostProvider(label string) string {
	switch label {
	case "ﾜｲﾜｲ":
		return "wi2"
	case "ｴﾑｿﾞﾈ", "ｽﾌﾟｯｯ", "ﾍﾟﾗﾍﾟﾗ":
		return "docomo"
	case "ﾜﾝﾄﾝｷﾝ":
		return "ocn"
	case "ﾌﾞｰｲﾓ":
		return "iij"
	case "ｵｲｺﾗﾐﾈｵ":
		return "optage"
	case "ﾍﾞｰｲﾓ":
		return "bmobile"
	case "ｱｳｱｳ":
		return "kddi"
	case "ｻｻｸｯﾃﾛ", "ｵｯﾍﾟｹ", "ｱ-ｸｾ-":
		return "softbank"
	}
	return ""
}

// hostRuleProvider は固定回線の共通表示でもサービス固有の運営分類を保持する。
func hostRuleProvider(rule HostRule) string {
	if rule.Provider != "" {
		return rule.Provider
	}
	return hostProvider(rule.Label)
}
