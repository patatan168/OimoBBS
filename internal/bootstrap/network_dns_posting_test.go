// 旧自動表とDNS確認結果から実HTTP投稿を行い、呼称の補正と再起動後のDATを確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
	"strings"
	"testing"
)

type postingDNSStatus struct{ status identity.HostDNSStatus }

func (v postingDNSStatus) Match(netip.Addr) (identity.NetworkClass, bool) {
	return identity.NetworkClass{}, false
}
func (v postingDNSStatus) DNSStatus(netip.Addr) identity.HostDNSStatus { return v.status }

func TestDNSNetworkPostingSuffixPersistence(t *testing.T) {
	for _, tc := range []struct {
		kind, label, suffix string
		status              identity.HostDNSStatus
		networkKind         string
		provider            string
	}{
		{"absent", "ｱﾝﾀﾀﾞﾚ", "h", identity.HostDNSAbsent, "fixed", "biglobe"},
		{"mismatch", "ZZ", "H", identity.HostDNSMismatch, "fixed", "biglobe"},
		{"confirmed", "ﾜｯﾁｮｲ", "0", identity.HostDNSConfirmed, "fixed", "biglobe"},
		{"mixed", "ﾃﾞｶﾁｷｭｰ", "0", identity.HostDNSConfirmed, "mixed", "biglobe"},
		{"unknown", "ﾃﾞｶﾁｷｭｰ", "0", identity.HostDNSConfirmed, "unknown", "biglobe"},
		{"unknown-freebit", "ﾀﾀﾞﾉｶｹﾗ", "0", identity.HostDNSConfirmed, "unknown", "freebit"},
		{"unknown-no-provider", "ﾜｶﾗﾝ", "0", identity.HostDNSConfirmed, "unknown", ""},
		{"unknown-other-provider", "ﾜｶﾗﾝ", "0", identity.HostDNSConfirmed, "unknown", "other"},
		{"unknown-absent", "ｱﾝﾀﾀﾞﾚ", "h", identity.HostDNSAbsent, "unknown", "freebit"},
		{"unknown-mismatch", "ZZ", "H", identity.HostDNSMismatch, "unknown", "freebit"},
		{"mixed-no-provider", "ﾜｯﾁｮﾏｾﾞ", "0", identity.HostDNSConfirmed, "mixed", ""},
		{"mixed-other-provider", "ﾜｯﾁｮﾏｾﾞ", "0", identity.HostDNSConfirmed, "mixed", "other"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			cfg, r := adminFixture(t)
			useHealthyPostingCapacity(t, r)
			board, err := r.CreateBoard(t.Context(), "special", "特殊回線")
			if err != nil {
				t.Fatal(err)
			}
			c := newAdminClient(t, r)
			if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
				t.Fatal("auth")
			}
			path := "/api/v1/boards/" + board.ID.String() + "/settings"
			res, body := c.request("GET", path, "", nil)
			var envelope struct {
				Data AdminBoard `json:"data"`
			}
			if json.Unmarshal([]byte(body), &envelope) != nil {
				t.Fatal("settings")
			}
			edit := envelope.Data.Settings
			edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "feature", AllowStrengthen: true, Networks: []identity.NetworkClass{}}
			raw, _ := json.Marshal(edit)
			res, body = c.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"special-display-0001"}})
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode, body)
			}
			classifier := *r.liveNetworks.Load()
			classifier.Automatic, err = identity.CompileNetworks([]identity.NetworkClass{{CIDR: "127.0.0.1/32", Kind: tc.networkKind, Label: "BIGLOBE", Suffix: "0", Provider: tc.provider}}, 1)
			if err != nil {
				t.Fatal(err)
			}
			classifier.Services = postingDNSStatus{tc.status}
			r.liveNetworks.Store(&classifier)
			r.mu.Lock()
			err = r.enableSpecialNetworkHosts()
			r.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			var site siteState
			if strictjson.Decode(r.site.State().Rows["site:state"].Value, &site) != nil || site.MinimumReader != dnsDisplayReader {
				t.Fatal("DNS display reader boundary")
			}
			form := formServer(t, r, siteID(r.site.State()), board.ID)
			post, err := sendForm(form, url.Values{"bbs": {"special"}, "subject": {"特殊回線"}, "MESSAGE": {"!extend:checked:vvvvv::\n本文"}, "oimo_request_id": {"special-posting-first-001"}})
			if err != nil || !post.Accepted {
				t.Fatal(post, err)
			}
			snap, err := r.Thread(context.Background(), board.ID, post.Key)
			if err != nil {
				t.Fatal(err)
			}
			dat, err := textcodec.Decode(snap.DAT)
			if err != nil || !strings.Contains(dat, "("+tc.label+" ") || !strings.Contains(dat, tc.suffix+"<>") || strings.Contains(dat, "BIGLOBE") {
				t.Fatal(dat, err)
			}
			original := string(snap.DAT)
			form.Close()
			c.server.Close()
			if err = r.Close(); err != nil {
				t.Fatal(err)
			}
			r, err = OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			snap, err = r.Thread(t.Context(), board.ID, post.Key)
			if err != nil || string(snap.DAT) != original {
				t.Fatal("DAT changed on restart", err)
			}
		})
	}
}
