// 管理資産の表示元を符号化しても、内部のページ要求にWAFが適用されることを検査する。
package bootstrap

import (
	"net/http"
	"testing"

	"oimobbs/internal/waf"
	"oimobbs/internal/webui"
)

func TestWAFAdminAssetSourceInspection(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	policy := WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()}
	policy.Traffic.Enabled = false
	repo.publishWAF(policy)
	for _, query := range []string{"ordinary", "UNION+SELECT"} {
		source := "/global-rules?q=" + query
		asset, err := webui.AdminAssetPath("admin-rules.css", "", source)
		if err != nil {
			t.Fatal(err)
		}
		want := http.StatusOK
		if query != "ordinary" {
			want = http.StatusForbidden
		}
		for _, path := range []string{source, asset} {
			res, _ := c.request("GET", path, "", nil)
			if res.StatusCode != want {
				t.Fatalf("page/source WAF mismatch: %s status=%d want=%d", path, res.StatusCode, want)
			}
		}
	}
	asset, err := webui.AdminAssetPath("ui.css", "", otpRoute+"register/qr")
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := c.request("GET", asset, "", nil); res.StatusCode != 404 {
		t.Fatal("asset lookup dispatched non-HTML authentication operation", res.StatusCode)
	}
}
