// 管理APIの特殊回線設定から実HTTP投稿を行い、名前欄・ID末尾と再起動後のDATを確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/textcodec"
	"strings"
	"testing"
)

func TestSpecialNetworkPostingSuffixPersistence(t *testing.T) {
	for _, tc := range []struct{ kind, label, suffix string }{{"hosting", "ｸﾓﾉｳｴ", "V"}, {"satellite", "ｳﾁｭｰ", "U"}} {
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
			edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "feature", AllowStrengthen: true, Networks: []identity.NetworkClass{{CIDR: "127.0.0.1/32", Kind: tc.kind, Label: tc.label, Suffix: tc.suffix}}}
			raw, _ := json.Marshal(edit)
			res, body = c.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"special-display-0001"}})
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode, body)
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
			if err != nil || !strings.Contains(dat, "("+tc.label+" ") || !strings.Contains(dat, tc.suffix+"<>") {
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
