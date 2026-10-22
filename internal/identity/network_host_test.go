// サービスDNSの確認、上書き優先、共有と停止の回帰試験。
package identity

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type hostTestResolver struct {
	mu      sync.Mutex
	names   []string
	ips     []netip.Addr
	calls   int
	started chan struct{}
	release chan struct{}
}

func (r *hostTestResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	if r.started != nil {
		select {
		case r.started <- struct{}{}:
		default:
		}
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r.names, nil
}
func (r *hostTestResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.ips, nil
}
func TestHostServicesConfirmed(t *testing.T) {
	ip := netip.MustParseAddr("153.140.37.173")
	cases := []struct{ host, label string }{
		{"p2642174-omed01.tokyo.ocn.ne.jp.", "ﾜﾝﾄﾝｷﾝ"},
		{"test.vmobile.jp.", "ﾌﾞｰｲﾓ"}, {"test.mineo.jp.", "ｵｲｺﾗﾐﾈｵ"},
		{"test.spmode.ne.jp.", "ｽﾌﾟｯｯ"}, {"test.au-net.ne.jp.", "ｱｳｱｳ"},
		{"test.panda-world.ne.jp.", "ｻｻｸｯﾃﾛ"},
		{"test.bmobile.ne.jp.", "ﾍﾞｰｲﾓ"}, {"test.mopera.net.", "ﾍﾟﾗﾍﾟﾗ"},
		{"test.openmobile.ne.jp.", "ｵｯﾍﾟｹ"}, {"test.access-internet.ne.jp.", "ｱ-ｸｾ-"},
		{"152.140.5.103.wi-fi.wi2.ne.jp.", "ﾜｲﾜｲ"}, {"dw49-106-188-132.m-zone.jp.", "ｴﾑｿﾞﾈ"},
		{"test.wi2.ne.jp.", ""}, {"test.m-zone.jp.attacker.example.", ""}, {"test.wi-fi.wi2.ne.jp.attacker.example.", ""},
		{"test.ipngn.ocn.ne.jp.", ""}, {"test.vmobile.jp.attacker.example.", ""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			resolver := &hostTestResolver{names: []string{tc.host}, ips: []netip.Addr{ip}}
			c := NewHostCache(resolver)
			defer c.Close()
			c.Resolve(context.Background(), ip)
			class, ok := c.Match(ip)
			if ok != (tc.label != "") || class.Label != tc.label {
				t.Fatal(class, ok)
			}
			c.Resolve(context.Background(), ip)
			if resolver.calls != 1 {
				t.Fatal("cache missed", resolver.calls)
			}
			if ok {
				classifier := &NetworkClassifier{Services: c}
				if got := classifier.Classify(nil, ip); got.Label != tc.label {
					t.Fatal(got)
				}
				override := NetworkClass{CIDR: "153.140.37.173/32", Kind: "fixed", Label: "manual", Suffix: "0"}
				classifier.Overrides, _ = CompileNetworks([]NetworkClass{override}, 1)
				if got := classifier.Classify(nil, ip); got.Label != "manual" {
					t.Fatal(got)
				}
				override.Label = "board"
				if got := classifier.Classify([]NetworkClass{override}, ip); got.Label != "board" {
					t.Fatal(got)
				}
			}
		})
	}
}
func TestHostForwardMismatchAndExpiry(t *testing.T) {
	ip := netip.MustParseAddr("153.140.37.173")
	resolver := &hostTestResolver{names: []string{"p1-omed01.tokyo.ocn.ne.jp"}, ips: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	c := NewHostCache(resolver)
	defer c.Close()
	now := time.Now()
	c.clock = func() time.Time { return now }
	c.Resolve(context.Background(), ip)
	if _, ok := c.Match(ip); ok {
		t.Fatal("unverified name accepted")
	}
	now = now.Add(31 * time.Second)
	resolver.ips = []netip.Addr{ip}
	c.Resolve(context.Background(), ip)
	if class, ok := c.Match(ip); !ok || class.Suffix != "M" {
		t.Fatal(class, ok)
	}
	now = now.Add(11 * time.Minute)
	if _, ok := c.Match(ip); ok {
		t.Fatal("expired classification")
	}
	for _, raw := range []string{"127.0.0.1", "192.0.2.1", "10.0.0.1", "2001:db8::1"} {
		c.Resolve(context.Background(), netip.MustParseAddr(raw))
	}
	if resolver.calls != 2 {
		t.Fatal(resolver.calls)
	}
}
func TestHostCoalescingCancellationAndClose(t *testing.T) {
	ip := netip.MustParseAddr("153.140.37.173")
	resolver := &hostTestResolver{started: make(chan struct{}, 8), release: make(chan struct{})}
	c := NewHostCache(resolver)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Resolve(ctx, ip); close(done) }()
	<-resolver.started
	cancel()
	<-done
	wait := make(chan struct{})
	go func() { c.Resolve(context.Background(), ip); close(wait) }()
	c.Close()
	<-wait
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.calls != 1 {
		t.Fatal(resolver.calls)
	}
	if _, ok := c.Match(ip); ok {
		t.Fatal("closed cache")
	}
}

func TestHostBounds(t *testing.T) {
	resolver := &hostTestResolver{started: make(chan struct{}, 64), release: make(chan struct{})}
	c := NewHostCache(resolver)
	var callers sync.WaitGroup
	for i := 0; i < 80; i++ {
		callers.Add(1)
		go func(i int) {
			defer callers.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			c.Resolve(ctx, netip.AddrFrom4([4]byte{153, 140, 37, byte(i + 1)}))
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-resolver.started
	}
	callers.Wait()
	c.mu.Lock()
	flights := len(c.flights)
	active := len(c.workers)
	c.mu.Unlock()
	if flights > 64 || active != 4 {
		t.Fatal("unbounded DNS", flights, active)
	}
	c.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.flights) != 0 {
		t.Fatal("pending DNS after close")
	}
}

func TestHostCacheCapacityAndIPv6(t *testing.T) {
	resolver := &hostTestResolver{}
	c := NewHostCache(resolver)
	defer c.Close()
	for i := 0; i < 1025; i++ {
		c.Resolve(context.Background(), netip.AddrFrom4([4]byte{153, 140, byte(i / 256), byte(i % 256)}))
	}
	c.mu.Lock()
	count := len(c.entries)
	c.mu.Unlock()
	if count != 1024 {
		t.Fatal(count)
	}
	ip := netip.MustParseAddr("2400:8500::1")
	resolver.names = []string{"test.vmobile.jp"}
	resolver.ips = []netip.Addr{ip}
	c.Resolve(context.Background(), ip)
	if class, ok := c.Match(ip); !ok || class.CIDR != "2400:8500::1/128" {
		t.Fatal(class, ok)
	}
	ip = netip.MustParseAddr("153.140.37.173")
	resolver.ips = []netip.Addr{ip}
	c.Resolve(context.Background(), netip.MustParseAddr("::ffff:153.140.37.173"))
	if class, ok := c.Match(ip); !ok || class.Suffix != "M" {
		t.Fatal(class, ok)
	}
}

func TestReverseIndependentOfClassification(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, names := range [][]string{{"dns.google."}, {}, {"bad..example."}, {"-bad.example."}} {
		c := NewHostCache(&hostTestResolver{names: names})
		c.Resolve(context.Background(), ip)
		if c.ReverseResolved(ip) != (len(names) > 0 && names[0] == "dns.google.") {
			t.Fatal(names)
		}
		if _, ok := c.Match(ip); ok {
			t.Fatal("generic PTR classified")
		}
		c.Close()
	}
}
func TestDNSModeDiscardsOldFlight(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	resolver := &hostTestResolver{names: []string{"test.vmobile.jp"}, ips: []netip.Addr{ip}, started: make(chan struct{}, 1), release: make(chan struct{})}
	c := NewHostCache(resolver)
	defer c.Close()
	done := make(chan struct{})
	go func() { c.Resolve(context.Background(), ip); close(done) }()
	<-resolver.started
	c.ConfigureDNS("google_https")
	close(resolver.release)
	<-done
	if c.ReverseResolved(ip) {
		t.Fatal("old DNS result published")
	}
	if _, ok := c.Match(ip); ok {
		t.Fatal("old classification published")
	}
}

// TestFixedHostServices は固定アクセスの名前空間、正引き一致、混在ISPの境界を検証する。
func TestFixedHostServices(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, tc := range []struct{ host, provider string }{
		{"subscriber.ap1.ftth.ucom.ne.jp.", "arteria"},
		{"subscriber.ap2.ftth.ucom.ne.jp", "arteria"},
		{"p123-ipngn2001.tokyo.ocn.ne.jp", "ocn"},
		{"example.ppp-bb.dion.ne.jp", "kddi"},
		{"p123.tokynt01.ap.so-net.ne.jp", "sonet"},
		{"fs123.tkyc201.ap.nuro.jp", "sonet"},
		{"example.ucom.ne.jp", ""},
		{"example.ftth.ucom.ne.jp.attacker.example", ""},
		{"example.ap.nuro.jp.attacker.example", ""},
		{"example.ocn.ne.jp", ""},
		{"example.dion.ne.jp", ""},
	} {
		t.Run(tc.host, func(t *testing.T) {
			for _, matched := range []bool{true, false} {
				forward := netip.MustParseAddr("1.1.1.1")
				if matched {
					forward = ip
				}
				cache := NewHostCache(&hostTestResolver{names: []string{tc.host}, ips: []netip.Addr{forward}})
				defer cache.Close()
				cache.Resolve(context.Background(), ip)
				class, ok := cache.Match(ip)
				want := matched && tc.provider != ""
				if ok != want || want && (class.Kind != "fixed" || class.Provider != tc.provider || class.Label != "ﾜｯﾁｮｲ" || class.Suffix != "0") {
					t.Fatal(matched, class, ok)
				}
			}
		})
	}
}
