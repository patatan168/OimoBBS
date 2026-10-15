// 実投稿の保全/ZIPと旧署名履歴でreader50の先行保存と製品再起動を検査する。
package bootstrap

import (
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"reflect"
	"testing"
	"time"
)

func TestLegacyExportCleanupReaderPersistsAcrossProductRestart(t *testing.T) {
	cfg, r, client, original, _ := requiredHTTPFixture(t)
	c, zip := createProductCleanupZIP(t, r, client, original)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	fillLegacyCaseControl(t, cfg, c, c.Creator, time.Now())
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Unix(0, int64(zip.Until))
	reopened.mu.Lock()
	e = reopened.prepareCaseExportCleanupLocked(at)
	reopened.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	checkProductCleanupReaderAndCase(t, reopened, c, 50)
	if e = reopened.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	checkProductCleanupReaderAndCase(t, reopened, c, 50)
}

func createProductCleanupZIP(t *testing.T, r *Repository, client *adminClient, original disclosure.Case) (disclosure.Case, disclosure.Export) {
	t.Helper()
	now := time.Now()
	input := disclosure.Case{Number: "legacy-zip-reader", Reason: "fixture", Scope: original.Scope, Until: domain.Time(now.Add(30 * 24 * time.Hour).UnixNano())}
	c, e := r.evidenceCases.Create(input, original.Creator, `"evidence:new"`, "legacy-zip-reader-create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, tokens := evidenceInfo(t, client, c.ID)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/hold"
	res, held, body := evidencePost(t, client, path, evidenceInput{Reason: "保全"}, c.ETag(), tokens[path], "legacy-zip-reader-hold")
	if res.StatusCode != 200 || held.State != "active" {
		t.Fatal(res.StatusCode, body)
	}
	c = held
	c, zip, e := r.evidenceCases.Generate(c.ID, c.Creator, c.ETag(), "legacy-zip-reader-export", "提出", []string{}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return c, zip
}

func checkProductCleanupReaderAndCase(t *testing.T, r *Repository, old disclosure.Case, reader uint32) {
	t.Helper()
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	if site.MinimumReader != reader {
		t.Fatal("reader not durable", site.MinimumReader)
	}
	c, e := r.evidenceCases.Get(old.ID)
	if e != nil {
		t.Fatal(e)
	}
	if c.State != old.State || c.Until != old.Until || !reflect.DeepEqual(c.Exports, old.Exports) {
		t.Fatal("preparation changed preservation")
	}
}
