// 復元先を別領域へ作り、現在の削除/非公開依頼/高水位を保存したまま再起動できることを確認する。
package bootstrap

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestPublicRestoreCompleteLatestRoot(t *testing.T) {
	cfg, repo, c, board, key := reportTestSetup(t)
	id, secret := createTestReport(t, c, key)
	admin := newAdminClient(t, repo)
	admin.login(adminTestSecret)
	path := "/api/v1/boards/" + board.String() + "/threads/" + key + "/moderation"
	res, body := admin.request("GET", path, "", nil)
	res, body = admin.request("POST", path, `{"kind":"hide","ranges":[],"hide_title":false}`, http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"restore-hide-0001"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	target := cfg
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	target.DataDir = filepath.Join(parent, "restored")
	if _, e := RestorePublicRepository(t.Context(), cfg, target); e == nil {
		t.Fatal("running source accepted")
	}
	c.server.Close()
	admin.server.Close()
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	report, e := RestorePublicRepository(t.Context(), cfg, target)
	if e != nil || !report.RestoreReady || report.Files == 0 || report.Bytes == 0 {
		t.Fatal(report, e)
	}
	restored, e := OpenPostingRepository(target, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	number, _ := strconv.ParseUint(key, 10, 64)
	snapshot, e := restored.Thread(t.Context(), board, number)
	if e != nil || snapshot != nil {
		t.Fatal("hidden thread resurrected", snapshot, e)
	}
	signing, e := reportKey(target.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	saved, e := readReport(target.DataDir, id, signing)
	if e != nil || !reportSecretMatches(saved, secret) {
		t.Fatal(saved, e)
	}
	copied, e := os.ReadFile(filepath.Join(target.DataDir, "keys", "master-000001.key"))
	if e != nil {
		t.Fatal(e)
	}
	source, e := os.ReadFile(filepath.Join(cfg.DataDir, "keys", "master-000001.key"))
	if e != nil || string(copied) != string(source) {
		t.Fatal(e)
	}
	if _, e := RestorePublicRepository(t.Context(), cfg, target); e == nil {
		t.Fatal("existing destination replaced")
	}
}

func TestPublicRestoreRejectsPartialAndLinks(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "復元検査"); e != nil {
		t.Fatal(e)
	}
	target := cfg
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	target.DataDir = filepath.Join(parent, "restored")
	if e := os.WriteFile(filepath.Join(cfg.DataDir, backupReplayGate), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := RestorePublicRepository(t.Context(), cfg, target); e == nil {
		t.Fatal("isolated backup root promoted")
	}
	os.Remove(filepath.Join(cfg.DataDir, backupReplayGate))
	if e := os.Symlink(filepath.Join(cfg.DataDir, "instance.json"), filepath.Join(cfg.DataDir, "tmp", "foreign")); e != nil {
		t.Fatal(e)
	}
	if _, e := RestorePublicRepository(t.Context(), cfg, target); e == nil {
		t.Fatal("symlink copied")
	}
	if _, e := os.Lstat(target.DataDir); !os.IsNotExist(e) {
		t.Fatal("failed restore published", e)
	}
	names, e := os.ReadDir(parent)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range names {
		if strings.HasPrefix(name.Name(), ".public-restore-") {
			t.Fatal("failed restore secrets retained")
		}
	}
}

func TestPublicRestoreReplaysKnownPreparingState(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "途中復元"); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	repo.mu.Lock()
	var site siteState
	if e = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	site.MinimumReader = 62
	activation := optionalLogActivation{Schema: "reports-activation-v1", Site: site.ID, Phase: "preparing"}
	if e = appendControl(repo.site, "reports_prepare", []store.Mutation{mutation("site", "state", site, nil), mutation("report_store", "active", activation, nil)}, []string{}); e != nil {
		t.Fatal(e)
	}
	repo.mu.Unlock()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	target := cfg
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	target.DataDir = filepath.Join(parent, "restored")
	if _, e = RestorePublicRepository(t.Context(), cfg, target); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(cfg.DataDir, "reports", reportDirectory)); !os.IsNotExist(e) {
		t.Fatal("source modified during replay", e)
	}
	if _, e = os.Stat(filepath.Join(target.DataDir, "reports", reportDirectory)); e != nil {
		t.Fatal(e)
	}
	if _, e = Check(target); e != nil {
		t.Fatal(e)
	}
}
