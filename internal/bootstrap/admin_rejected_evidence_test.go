// 未受理の現用接続行を実管理HTTPから照会・署名提出・一回取得し、製品再起動まで検査する。
package bootstrap

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminRejectedEvidenceHTTP(t *testing.T) {
	cfg, repo, board := postingRepositoryFixture(t)
	if _, e := repo.ConfigureAdministrator("owner", "所有者", adminTestSecret, false); e != nil {
		t.Fatal(e)
	}
	repo = reopenRejectedProduct(t, cfg, repo)
	if _, e := repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	repo = reopenRejectedProduct(t, cfg, repo)
	raw, at := agedRejectedFrame(t)
	key, e := repo.ReserveThreadKey(t.Context(), board.ID, time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	appendRejectedProposal(t, repo, board.ID, key, raw, at)
	repo = reopenRejectedProduct(t, cfg, repo)
	defer func() { _ = repo.Close() }()
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	list, _ := client.request("GET", "/api/v1/evidence/cases", "", nil)
	input := evidenceInput{Number: "REJECTED-1", Reason: "未受理記録の確認", Scope: disclosure.Scope{Board: board.ID, Thread: domain.U64(key), From: at - 1, To: at + 1, Records: []domain.ID{}}}
	res, c, body := evidencePost(t, client, "/api/v1/evidence/cases", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 || c.State != "draft" {
		t.Fatal(res.StatusCode, body)
	}
	page, html := client.request("GET", "/evidence", "", nil)
	if page.StatusCode != 200 || !strings.Contains(html, "保存状況") || !strings.Contains(html, "対象は未確定") {
		t.Fatal(page.StatusCode, html)
	}
	c, tokens := evidenceInfo(t, client, c.ID)
	query := "/api/v1/evidence/cases/" + c.ID.String() + "/rejected-query"
	before := c.Revision
	res, _, body = evidencePost(t, client, query, map[string]any{"reason": "禁止列", "columns": []string{"content"}}, c.ETag(), tokens[query], domain.NewID().String())
	if res.StatusCode != 404 {
		t.Fatal("retired query accepted", res.StatusCode, body)
	}
	current, _ := evidenceInfo(t, client, c.ID)
	if current.Revision != before {
		t.Fatal("invalid request audited as successful")
	}
	res, _, body = evidencePost(t, client, query, evidenceInput{Reason: "接続記録確認"}, c.ETag(), tokens[query], domain.NewID().String())
	if res.StatusCode != 404 {
		t.Fatal("retired rejected query", res.StatusCode, body)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	exports := "/api/v1/evidence/cases/" + c.ID.String() + "/rejected-exports"
	res, c, body = evidencePost(t, client, exports, evidenceInput{Reason: "提出準備"}, c.ETag(), tokens[exports], domain.NewID().String())
	if res.StatusCode != 200 || len(c.Exports) != 1 || c.Exports[0].Kind != "not_accepted" || c.Exports[0].State != "ready" {
		t.Fatal(res.StatusCode, body)
	}
	v := c.Exports[0]
	if v.Until > at+domain.Time(7*24*time.Hour) {
		t.Fatal("source retention extended", v.Until)
	}
	site, _, e := repo.requiredGCJob(time.Now())
	if e != nil || site.MinimumReader != 55 {
		t.Fatal(site.MinimumReader, e)
	}
	client.server.Close()
	repo = reopenRejectedProduct(t, cfg, repo)
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login after restart")
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	download := "/api/v1/evidence/exports/" + v.ID.String() + "/download"
	res, _, body = evidencePost(t, client, download, evidenceInput{CaseID: c.ID, Reason: "手動取得"}, c.ETag(), tokens[download], domain.NewID().String())
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/zip" {
		t.Fatal(res.StatusCode, body)
	}
	seed, e := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"))
	if e != nil {
		t.Fatal(e)
	}
	signing := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(signing)
	m, e := disclosure.VerifyZIP(bytes.NewReader([]byte(body)), int64(len(body)), signing.Public().(ed25519.PublicKey))
	if e != nil || m.RecordKind != "not_accepted" || m.Count != 1 || len(m.Columns) != 1 || m.Columns[0] != "connection" {
		t.Fatal(m, e)
	}
	z, e := zip.NewReader(bytes.NewReader([]byte(body)), int64(len(body)))
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range z.File {
		if f.Name == "readme.txt" {
			checkRejectedZIPLogExplanation(t, f)
		}
		if f.Name == "records.csv" {
			r, e := f.Open()
			if e != nil {
				t.Fatal(e)
			}
			content, e := io.ReadAll(r)
			r.Close()
			if e != nil {
				t.Fatal(e)
			}
			rows := evidenceCSVRows(t, content)
			if len(rows) != 1 || rows[0]["completeness"] != "partial" || rows[0]["proposal_event_sha256"] == "" {
				t.Fatal("CSV rejected record")
			}
			if rows[0]["connection"] != `\N` || rows[0]["connection_missing_reason"] != "not_collected" {
				t.Fatal("unrecorded connection must remain explicitly missing")
			}

		}
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	res, _, body = evidencePost(t, client, download, evidenceInput{CaseID: c.ID, Reason: "二回目"}, c.ETag(), tokens[download], domain.NewID().String())
	if res.StatusCode == http.StatusOK {
		t.Fatal("one-use download reused", body)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	hold := "/api/v1/evidence/cases/" + c.ID.String() + "/rejected-hold"
	res, c, body = evidencePost(t, client, hold, evidenceInput{Reason: "未受理の接続保全"}, c.ETag(), tokens[hold], domain.NewID().String())
	if res.StatusCode != 200 || c.Rejected == nil || c.Rejected.State != "active" || c.State != "active" {
		t.Fatal("hold", res.StatusCode, body)
	}
	site, _, e = repo.requiredGCJob(time.Now())
	if e != nil || site.MinimumReader != 55 {
		t.Fatal(site.MinimumReader, e)
	}
	client.server.Close()
	repo = reopenRejectedProduct(t, cfg, repo)
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("held restart login")
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	res, _, body = evidencePost(t, client, query, evidenceInput{Reason: "保全コピーの照会"}, c.ETag(), tokens[query], domain.NewID().String())
	if res.StatusCode != 404 || c.Rejected == nil || c.Rejected.State != "active" {
		t.Fatal("retired held query", res.StatusCode, body)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	res, c, body = evidencePost(t, client, exports, evidenceInput{Reason: "保全コピーの提出"}, c.ETag(), tokens[exports], domain.NewID().String())
	if res.StatusCode != 200 || len(c.Exports) != 2 || !c.Exports[1].RejectedHeld {
		t.Fatal("held export", res.StatusCode, body)
	}
	assertOtherDirectExtraction(t, client, repo, cfg, c, false)
	release := "/api/v1/evidence/cases/" + c.ID.String() + "/release"
	c, tokens = evidenceInfo(t, client, c.ID)
	res, c, body = evidencePost(t, client, release, evidenceInput{Reason: "未受理保全の解除"}, c.ETag(), tokens[release], domain.NewID().String())
	if res.StatusCode != 200 || c.State != "closed" || c.Rejected.State != "removed" {
		t.Fatal("held release", res.StatusCode, body)
	}
}

// checkRejectedZIPLogExplanation は実製品で生成した署名対象の確認状況を検査する。
func checkRejectedZIPLogExplanation(t *testing.T, file *zip.File) {
	t.Helper()
	r, e := file.Open()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	raw, e := io.ReadAll(r)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), "ログの確認範囲と欠落") || !strings.Contains(string(raw), "原本へ照合") {
		t.Fatal(string(raw))
	}
}
