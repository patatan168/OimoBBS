// 簡素化した提出画面と、別入口からの未受理・閲覧ZIP取得を検査する。
package bootstrap

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
)

// assertOtherDirectExtraction は保全前から一操作で固定コピー・署名ZIP・一回取得まで進むことを確認する。
func assertOtherDirectExtraction(t *testing.T, client *adminClient, repo *Repository, cfg Config, source disclosure.Case, httpOnly bool) {
	t.Helper()
	list, _ := client.request("GET", "/api/v1/evidence/cases", "", nil)
	info, body := client.request("GET", "/api/v1/evidence/cases/"+source.ID.String(), "", nil)
	if info.StatusCode != 200 {
		t.Fatal(body)
	}
	var wire evidenceListReply
	if err := json.Unmarshal([]byte(body), &wire); err != nil {
		t.Fatal(err)
	}
	input := evidenceInput{Number: "DIRECT-" + domain.NewID().String(), Reason: "別入口から全項目を取得", Scope: source.Scope}
	res, c, body := evidencePost(t, client, "/api/v1/evidence/other-cases", input, list.Header.Get("ETag"), wire.Tokens["/api/v1/evidence/other-cases"], domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal("create other case", res.StatusCode, body)
	}
	c, csrf := evidenceInfo(t, client, c.ID)
	suffix, kind := "extract-rejected", "not_accepted"
	if httpOnly {
		suffix, kind = "extract-http", "http_observation"
	}
	route := "/api/v1/evidence/cases/" + c.ID.String() + "/" + suffix
	before := c.Revision
	res, _, body = evidencePost(t, client, route, evidenceInput{Reason: input.Reason}, `"stale"`, csrf[route], domain.NewID().String())
	if res.StatusCode != 412 {
		t.Fatal("stale direct extraction", res.StatusCode, body)
	}
	c, _ = evidenceInfo(t, client, c.ID)
	if c.Revision != before {
		t.Fatal("stale extraction changed case")
	}
	formPath := strings.TrimPrefix(route, "/api/v1")
	page, html := client.request("GET", "/evidence?kind=other&q="+input.Number, "", nil)
	form := regexp.MustCompile(`(?s)<form[^>]*action="` + regexp.QuoteMeta(formPath) + `"[^>]*>(.*?)</form>`).FindStringSubmatch(html)
	if page.StatusCode != 200 || len(form) != 2 {
		t.Fatal("other extract form", page.StatusCode, html)
	}
	fields := pageFields(form[1])
	fields.Set("reason", input.Reason)
	res, body = client.request("POST", formPath, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})

	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/zip" {
		t.Fatal("direct other ZIP", res.StatusCode, body)
	}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), 32)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(key)
	manifest, e := disclosure.VerifyZIP(bytes.NewReader([]byte(body)), int64(len(body)), key.Public().(ed25519.PublicKey))
	if e != nil || manifest.RecordKind != kind || manifest.Count < 1 || len(manifest.Columns) != 1 {
		t.Fatal("other signed ZIP", manifest, e)
	}
	archive, e := zip.NewReader(bytes.NewReader([]byte(body)), int64(len(body)))
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range archive.File {
		if file.Name == "records.csv" {
			r, e := file.Open()
			if e != nil {
				t.Fatal(e)
			}
			raw, e := io.ReadAll(r)
			r.Close()
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(raw, []byte("PRIVATE_INPUT_NEVER_COPY")) || bytes.Contains(raw, []byte("PRIVATE-REJECTED")) {
				t.Fatal("private input leaked")
			}
		}
	}
	c, csrf = evidenceInfo(t, client, c.ID)
	if c.State != "active" || len(c.Exports) != 1 || c.Exports[0].State != "consumed" {
		t.Fatal("direct extraction did not finish", c.State, c.Exports)
	}
	if httpOnly {
		if c.HTTP == nil || !c.HTTP.Unbound || c.HTTP.State != "active" {
			t.Fatal("HTTP not held")
		}
	} else if c.Rejected == nil || c.Rejected.State != "active" {
		t.Fatal("rejected not held")
	}
	for _, kind := range []string{"posts", "other"} {
		q := url.Values{"q": {input.Number}, "kind": {kind}}
		found := readEvidenceList(t, client, "/api/v1/evidence/cases?"+q.Encode())
		want := 0
		if kind == "other" {
			want = 1
		}
		if found.Total != want {
			t.Fatal("case kinds mixed", kind, found.Total)
		}
	}
	if httpOnly {
		// 元HTTPの収集が停止していても、保全済みコピーの取得は継続できる。
		repo.mu.Lock()
		sourceStore := repo.optionalStore
		repo.optionalStore = nil
		repo.mu.Unlock()
		response, _, payload := evidencePost(t, client, route, evidenceInput{Reason: "収集停止後の保全コピー取得"}, c.ETag(), csrf[route], domain.NewID().String())
		repo.mu.Lock()
		repo.optionalStore = sourceStore
		repo.mu.Unlock()
		if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/zip" {
			t.Fatal("held HTTP requires live source", response.StatusCode, payload)
		}
		c, csrf = evidenceInfo(t, client, c.ID)
	}
	page, html = client.request("GET", "/evidence?kind=other&q="+input.Number, "", nil)
	if page.StatusCode != 200 || !strings.Contains(html, "ZIPの作成・取得履歴") || strings.Contains(html, "手動受渡し") || strings.Contains(html, "記録を照会") || strings.Contains(html, "受付前拒否・閲覧を照会") {
		t.Fatal("other page", page.StatusCode, html)
	}
	for _, old := range []string{"/evidence/query", "/evidence/cases/" + c.ID.String() + "/rejected-query", "/evidence/cases/" + c.ID.String() + "/http-query", "/evidence/exports/" + c.Exports[0].ID.String() + "/transfers"} {
		for _, prefix := range []string{"", "/api/v1"} {
			response, _ := client.request("POST", prefix+old, `{}`, http.Header{"Content-Type": {"application/json"}})
			if response.StatusCode != 404 {
				t.Fatal("removed route", prefix+old, response.StatusCode)
			}
		}
	}
	release := "/api/v1/evidence/cases/" + c.ID.String() + "/release"
	res, _, body = evidencePost(t, client, release, evidenceInput{Reason: "検査終了"}, c.ETag(), csrf[release], domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal("release direct case", res.StatusCode, body)
	}
}

func TestEvidenceSimpleActions(t *testing.T) {
	now := time.Now()
	session := adminauth.Session{}
	for _, state := range []string{"draft", "active", "partial", "preparing", "closed", "releasing"} {
		c := disclosure.Case{ID: domain.NewID(), State: state, Until: domain.Time(now.Add(time.Hour).UnixNano())}
		row := evidenceRow{Case: c}
		configureEvidenceActions(&row, session, "posts", now)
		for _, a := range row.Actions {
			if a.Label != "保全期限を延長" && a.Label != "保全を終了" && a.Label != "保全処理を再開" {
				t.Fatal("unnecessary action", state, a)
			}
		}
		if state == "closed" && len(row.Actions) > 0 {
			t.Fatal("closed actions")
		}
		if state != "preparing" {
			for _, a := range row.Actions {
				if a.Label == "保全処理を再開" {
					t.Fatal("recovery outside failure")
				}
			}
		}
	}
	c := disclosure.Case{ID: domain.NewID(), State: "active", Until: domain.Time(now.Add(time.Hour).UnixNano()), Exports: []disclosure.Export{
		{ID: domain.NewID(), State: "ready", Created: domain.Time(now.Add(-2 * time.Hour).UnixNano()), Until: domain.Time(now.Add(-time.Hour).UnixNano())},
		{ID: domain.NewID(), State: "preparing", Created: domain.Time(now.Add(-time.Minute).UnixNano()), Until: domain.Time(now.Add(time.Hour).UnixNano())},
	}}
	row := evidenceRow{Case: c}
	configureEvidenceActions(&row, session, "posts", now)
	if len(row.Exports) != 2 || row.Exports[0].Recoverable || row.Exports[0].StateLabel != "期限切れ" || !row.Exports[1].Recoverable {
		t.Fatal("expired ZIP recovery shown", row.Exports)
	}
	for _, raw := range []string{`{"transfer":null}`, `{"transfer":{}}`, `{"method":"email"}`, `{"acknowledged":true}`} {
		var input evidenceInput
		if decodeEvidenceInput([]byte(raw), &input) == nil {
			t.Fatal("retired transfer input", raw)
		}
	}
}
