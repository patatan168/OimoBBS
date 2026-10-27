// 確認済みサービス分類が投稿表示・板規制・キャップ例外まで届くことを検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/textcodec"
	"strings"
	"sync/atomic"
	"testing"
)

func TestServiceNetworkPostingAndCap(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, err := r.CreateBoard(context.Background(), "service", "サービス分類")
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	path := "/api/v1/boards/" + board.ID.String() + "/settings"
	res, body := client.request("GET", path, "", nil)
	var settings struct {
		Data AdminBoard `json:"data"`
	}
	if json.Unmarshal([]byte(body), &settings) != nil {
		t.Fatal("settings")
	}
	edit := settings.Data.Settings
	edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "feature", AllowStrengthen: true, Networks: []identity.NetworkClass{}}
	raw, _ := json.Marshal(edit)
	res, body = client.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"service-settings"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	// HTTP観測は実ソケットのループバックを保持する。DNS確認部分はidentityの試験で独立検証する。
	table, err := identity.CompileNetworks([]identity.NetworkClass{{CIDR: "127.0.0.1/32", Kind: "mvno", Label: "ﾜﾝﾄﾝｷﾝ", Suffix: "M"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	classifier := *r.liveNetworks.Load()
	classifier.Services = table
	r.liveNetworks.Store(&classifier)
	form := formServer(t, r, siteID(r.site.State()), board.ID)
	defer form.Close()
	post, err := sendForm(form, url.Values{"bbs": {"service"}, "subject": {"DNS分類"}, "MESSAGE": {"!extend:checked:vvvvv::\n本文"}, "oimo_request_id": {"service-first-create"}})
	if err != nil || !post.Accepted {
		t.Fatal(post, err)
	}
	snap, err := r.Thread(context.Background(), board.ID, post.Key)
	if err != nil {
		t.Fatal(err)
	}
	dat, err := textcodec.Decode(snap.DAT)
	if err != nil || !strings.Contains(dat, "(ﾜﾝﾄﾝｷﾝ") || !strings.Contains(dat, "M<") {
		t.Fatal("service display", err)
	}
	var live atomic.Pointer[identity.NetworkClassifier]
	live.Store(&classifier)
	b := &postingBoard{liveNetworks: &live}
	deny := &NetworkAccessSettings{AllowVPN: true, DeniedKinds: []string{"mvno"}}
	ip := netip.MustParseAddr("127.0.0.1")
	if b.checkNetworkAccess(deny, ip, false) != ErrNetworkPermission {
		t.Fatal("MVNO permission bypass")
	}
	if b.checkNetworkAccess(deny, ip, true) != nil {
		t.Fatal("cap exemption")
	}

	// 逆引き不可のループバック接続を拒否する板設定を保存し、実HTTP入口で検査する。
	current, _ := client.request("GET", path, "", nil)
	edit.Identity.Access = &NetworkAccessSettings{AllowVPN: true, DenyUnresolvedHost: reverseFlag(true)}
	raw, _ = json.Marshal(edit)
	changed, changedBody := client.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {current.Header.Get("X-CSRF-Token")}, "If-Match": {current.Header.Get("ETag")}, "Idempotency-Key": {"service-reverse-deny"}})
	if changed.StatusCode != 200 {
		t.Fatal(changed.StatusCode, changedBody)
	}
	deniedReply, err := sendForm(form, url.Values{"bbs": {"service"}, "key": {fmt.Sprint(post.Key)}, "MESSAGE": {"通常投稿"}, "oimo_request_id": {"service-denied-reply"}})
	if err != nil || deniedReply.Accepted {
		t.Fatal("unresolved host accepted", deniedReply, err)
	}
	retry, err := sendForm(form, url.Values{"bbs": {"service"}, "subject": {"DNS分類"}, "MESSAGE": {"!extend:checked:vvvvv::\n本文"}, "oimo_request_id": {"service-first-create"}})
	if err != nil || !retry.Accepted || retry.Key != post.Key {
		t.Fatal("accepted retry lost", retry, err)
	}
	cap, key := createTestCap(t, r, client, board.ID, []string{"post"})
	reply, err := sendForm(form, url.Values{"bbs": {"service"}, "key": {fmt.Sprint(post.Key)}, "MESSAGE": {"管理投稿"}, "mail": {"#cap:" + cap.ID.String() + ":" + key}, "oimo_request_id": {"service-cap-reply"}})
	if err != nil || !reply.Accepted {
		t.Fatal(reply, err)
	}
}

// serviceProbeResolver はHTTP管理照会のDNS補完をネットワークなしで再現する。
type serviceProbeResolver struct{}

func (serviceProbeResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"p2642174-omed01.tokyo.ocn.ne.jp."}, nil
}
func (serviceProbeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("153.140.37.173")}, nil
}
func TestServiceNetworkProbe(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	r.networkHosts.Close()
	r.networkHosts = identity.NewHostCache(serviceProbeResolver{})
	classifier := *r.liveNetworks.Load()
	classifier.Services = r.networkHosts
	r.liveNetworks.Store(&classifier)
	probe, err := r.probeNetworkContext(context.Background(), " 153.140.37.173 ")
	if err != nil || !probe.ReverseResolved || probe.Class.Label != "ﾜﾝﾄﾝｷﾝ" || probe.Class.Suffix != "M" || probe.Hostname != "p2642174-omed01.tokyo.ocn.ne.jp" || probe.Origin != "逆引き・正引きで確認したサービス" {
		t.Fatal(probe, err)
	}
	classifier.Overrides, _ = identity.CompileNetworks([]identity.NetworkClass{{CIDR: "153.140.37.173/32", Kind: "fixed", Label: "上書き", Suffix: "0"}}, 1)
	r.liveNetworks.Store(&classifier)
	probe, err = r.probeNetworkContext(context.Background(), "153.140.37.173")
	if err != nil || probe.Class.Label != "上書き" || probe.Hostname != "" {
		t.Fatal(probe, err)
	}
}

func TestReversePermissionIndependentOfService(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	r.networkHosts.Close()
	r.networkHosts = identity.NewHostCache(serviceProbeResolver{})
	classifier := *r.liveNetworks.Load()
	classifier.Services = r.networkHosts
	r.liveNetworks.Store(&classifier)
	b := &postingBoard{liveNetworks: &r.liveNetworks}
	ip := netip.MustParseAddr("8.8.8.8")
	settings := &NetworkAccessSettings{AllowVPN: true, DenyUnresolvedHost: reverseFlag(true)}
	if b.checkNetworkAccess(settings, ip, false) != ErrUnresolvedHost {
		t.Fatal("pending DNS allowed")
	}
	if message, status := networkAccessMessage(ErrUnresolvedHost); status != 403 || !strings.Contains(message, "逆引き") {
		t.Fatal(message, status)
	}
	// PTR取得成功でも正引きは別IPなのでサービス分類は採用しない。
	r.networkHosts.Resolve(context.Background(), ip)
	if _, ok := r.networkHosts.Match(ip); ok {
		t.Fatal("forward mismatch accepted")
	}
	if b.checkNetworkAccess(settings, ip, false) != nil {
		t.Fatal("PTR success denied")
	}
	if b.checkNetworkAccess(settings, netip.MustParseAddr("127.0.0.1"), true) != nil {
		t.Fatal("cap denied")
	}
	settings.DenyUnresolvedHost = reverseFlag(false)
	if b.checkNetworkAccess(settings, netip.MustParseAddr("127.0.0.1"), false) != nil {
		t.Fatal("default deny")
	}
}
