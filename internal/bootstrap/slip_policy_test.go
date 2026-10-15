// 全投稿Cookie必須化、プロバイダ保存、DAT、再起動を実HTTPで検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/textcodec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSlipV2CookiePolicyAndRecovery(t *testing.T) {
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}

	if err := repo.EnableSlip(); err != nil {
		t.Fatal("activation", err)
	}
	activation := repo.site.State().Rows["slip_policy:active"]
	if err := repo.EnableSlip(); err != nil || !reflect.DeepEqual(activation, repo.site.State().Rows["slip_policy:active"]) {
		t.Fatal("idempotent activation", err)
	}
	res, v := c.board(board.String())
	if v.Settings.Anonymous == nil || v.Settings.Anonymous.Mode != "required" {
		t.Fatal("mandatory board setting missing", v)
	}
	edit := v.Settings
	edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "vvvvv", AllowStrengthen: true, Networks: []identity.NetworkClass{{CIDR: "127.0.0.0/8", Kind: "fixed", Label: "OCN", Suffix: "0", Provider: "ocn"}}}
	rates := defaultRateSettings()
	rates.Enabled = false
	edit.Rates = &rates
	raw, _ := json.Marshal(edit)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"slip-v2-board-settings"}}
	res, page := c.request("PATCH", "/api/v1/boards/"+board.String()+"/settings", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, page)
	}
	_, page = c.request("GET", "/boards/"+board.String()+"/settings", "", nil)
	if strings.Contains(page, `<option value="off"`) || !strings.Contains(page, `name="network_provider" value="ocn"`) {
		t.Fatal("cookie/provider form mismatch", page)
	}
	// サイト・板の管理APIから必須条件を解除できない。
	res, v = c.board(board.String())
	edit = v.Settings
	edit.Anonymous = &AdminAnonymousSettings{Mode: "off"}
	raw, _ = json.Marshal(edit)
	headers.Set("If-Match", res.Header.Get("ETag"))
	headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
	headers.Set("Idempotency-Key", "slip-v2-reject-off")
	res, page = c.request("PATCH", "/api/v1/boards/"+board.String()+"/settings", string(raw), headers)
	if res.StatusCode != 422 || !strings.Contains(page, "COOKIE_REQUIRED") {
		t.Fatal("board weakened", res.StatusCode, page)
	}
	c.reauthAnonymous()
	res, anon := c.anonymous()
	res, page = c.request("POST", "/api/v1/anonymous", `{"mode":"optional"}`, http.Header{"Content-Type": {"application/json"}, "If-Match": {anon.ETag()}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"slip-v2-site-optional"}})
	if res.StatusCode != 400 || !strings.Contains(page, "INVALID_JSON") {
		t.Fatal("removed mode accepted", res.StatusCode, page)
	}
	server, request, cookies := anonymousHTTP(t, repo, siteID(repo.site.State()))
	defer func() { server.Close() }()
	fields := url.Values{"bbs": {"news"}, "subject": {"独自ワッチョイ"}, "MESSAGE": {"本文"}, "oimo_request_id": {"slip-v2-create-thread"}}
	res, page = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || !strings.Contains(page, "2ch_X:cookie") || cookies["oimo_anon"] == nil {
		t.Fatal("cookie confirmation", res.StatusCode, page)
	}
	rows, err := repo.rateHistory()
	if err != nil || len(rows) != 0 {
		t.Fatal("saved without cookie", rows, err)
	}
	res, page = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || strings.Contains(page, "ERROR:") || strings.Contains(page, "2ch_X:cookie") {
		t.Fatal("valid cookie rejected", res.StatusCode, page)
	}
	rows, err = repo.rateHistory()
	if err != nil || len(rows) != 1 || rows[0].record.TokenStatus != "valid" {
		t.Fatal(rows, err)
	}
	key := rows[0].key
	snap, err := repo.Thread(context.Background(), board, key)
	if err != nil || !strings.Contains(string(snap.DAT), "</b>(") {
		t.Fatal("DAT missing", err)
	}
	original := append([]byte{}, snap.DAT...)
	token, err := repo.anonymous.verify(cookies["oimo_anon"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b := repo.posting[board]
	want, err := identity.Slip(b.slipNetKey[:], b.slipUAKey[:], board, time.Unix(0, int64(rows[0].record.At)), netip.MustParseAddr("127.0.0.1"), "ocn", token.ID, "Go-http-client/1.1")
	dat, decodeErr := textcodec.Decode(snap.DAT)
	if err != nil || decodeErr != nil || !strings.Contains(dat, "</b>(ﾜｯﾁｮｲ "+want+")<b>") {
		t.Fatal("unexpected identity", dat, want, err, decodeErr)
	}
	// 確認Cookieがあっても匿名Cookieを返さなければ返信を受理しない。
	delete(cookies, "oimo_anon")
	fields.Del("subject")
	fields.Set("key", strconv.FormatUint(key, 10))
	fields.Set("oimo_request_id", "slip-v2-missing-cookie")
	_, _ = request("POST", "/test/bbs.cgi", fields)
	rows, err = repo.rateHistory()
	if err != nil || len(rows) != 1 {
		t.Fatal("reply bypass", rows, err)
	}
	server.Close()
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	if !repo.liveSlipEnabled.Load() || !reflect.DeepEqual(activation, repo.site.State().Rows["slip_policy:active"]) {
		t.Fatal("activation lost")
	}
	snap, err = repo.Thread(context.Background(), board, key)
	if err != nil || !reflect.DeepEqual(original, snap.DAT) {
		t.Fatal("DAT changed", err)
	}
}
