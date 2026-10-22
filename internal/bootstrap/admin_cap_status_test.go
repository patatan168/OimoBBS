// キャップの削除・期限境界と、実際の管理テンプレートの状態表示を検証する。
package bootstrap

import (
	"bytes"
	"oimobbs/internal/domain"
	"strings"
	"testing"
)

func TestAdminCapStatusExpiryBoundary(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enabled bool
		expires domain.Time
		want    string
	}{
		{"unlimited", true, 0, "有効"},
		{"before", true, 101, "有効"},
		{"at", true, 100, "期限切れ"},
		{"after", true, 99, "期限切れ"},
		{"revoked", false, 101, "削除済み"},
		{"revoked expired", false, 99, "削除済み"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := AdminCap{Enabled: tt.enabled, Expires: tt.expires}
			if got := capStatusAt(v, 100); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
	var body bytes.Buffer
	page := capsPage{Rows: []capRow{{AdminCap: AdminCap{Name: "期限が過ぎた資格", Enabled: true, Expires: 1}}}}
	if err := capsTemplate.Execute(&body, page); err != nil {
		t.Fatal(err)
	}
	html := body.String()
	if !strings.Contains(html, `admin-badge-off">期限切れ</span>`) || strings.Contains(html, `admin-badge-on">有効</span>`) || !strings.Contains(html, "変更して鍵を再発行") {
		t.Fatal("expired cap must show expired and retain renewal controls")
	}
}
