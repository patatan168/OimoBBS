// 板名・キー変更の担当外拒否、旧キー予約、同時投稿、SIGKILL後の一括復旧を検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func TestBoardMetadataSiteAdministratorOnly(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "limited", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CreateAdministrator("boardowner", "板管理者", adminTestSecret, AdministratorAccess{Role: "board_admin", Boards: []domain.ID{board.ID}, Permissions: []string{}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	_, page := c.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", "boardowner")
	fields.Set("password", adminTestSecret)
	res, _ := c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("login", res.StatusCode)
	}
	for _, path := range []string{"/boards/new", "/boards/" + board.ID.String() + "/metadata", "/boards/" + domain.NewID().String() + "/metadata"} {
		for _, method := range []string{"GET", "POST"} {
			res, body := c.request(method, path, "", nil)
			if res.StatusCode != 403 || strings.Contains(body, `name="key"`) {
				t.Fatal("unauthorized metadata", method, path, res.StatusCode)
			}
		}
	}
	res, page = c.request("GET", "/boards/"+board.ID.String()+"/settings", "", nil)
	if res.StatusCode != 200 || strings.Contains(page, "板名・キーを変更") {
		t.Fatal("site-only link exposed", res.StatusCode)
	}
}

func TestBoardDirectoryMetadataValidation(t *testing.T) {
	d := boardDirectory{Key: "current", Aliases: []string{"original"}, Name: "変更済み", Status: "active", JobID: domain.NewID()}
	if d.validateMetadata() != nil {
		t.Fatal("valid metadata")
	}
	for _, aliases := range [][]string{{"current"}, {"z", "a"}, {"original", "original"}, {"../escape"}, {"admin"}} {
		bad := d
		bad.Aliases = aliases
		if bad.validateMetadata() == nil {
			t.Fatal("invalid aliases", aliases)
		}
	}
	next := d
	next.Aliases = []string{}
	if validateMetadataTransition(d, next) == nil {
		t.Fatal("forgot old key")
	}
	for _, raw := range []string{`{"key":"a"}`, `{"key":"a","aliases":[],"status":"active","category_id":null,"job_id":"` + d.JobID.String() + `","name":""}`, `{"key":"a","aliases":[],"status":"active","category_id":null,"job_id":"` + d.JobID.String() + `","unknown":1}`} {
		var decoded boardDirectory
		if strictjson.Decode([]byte(raw), &decoded) == nil {
			t.Fatal("incomplete directory accepted", raw)
		}
	}
	// 新形式の登録を古いreader境界で読み込ませない。
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "original", "元")
	if err != nil {
		t.Fatal(err)
	}
	state := repo.site.State()
	state.Rows = maps.Clone(state.Rows)
	row := state.Rows["board_directory:"+board.ID.String()]
	if err := strictjson.Decode(row.Value, &d); err != nil {
		t.Fatal(err)
	}
	d.Name = "変更済み"
	d.Key = "current"
	d.Aliases = []string{"original"}
	row.Value, _ = json.Marshal(d)
	state.Rows["board_directory:"+board.ID.String()] = row
	var site siteState
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		t.Fatal(err)
	}
	site.MinimumReader = boardMetadataReader - 1
	siteRow := state.Rows["site:state"]
	siteRow.Value, _ = json.Marshal(site)
	state.Rows["site:state"] = siteRow
	if _, err := siteDirectories(state); err == nil {
		t.Fatal("missing reader boundary accepted")
	}
}

func TestBoardMetadataDuringPosting(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	useHealthyPostingCapacity(t, repo)
	board, err := repo.CreateBoard(t.Context(), "original", "同時投稿")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	done := make(chan error, 1)
	go func() {
		for i := range 8 {
			v, e := sendForm(form, url.Values{"bbs": {"original"}, "subject": {fmt.Sprint("投稿", i)}, "MESSAGE": {"変更中の投稿"}, "oimo_request_id": {fmt.Sprint("metadata-concurrent-", i)}})
			if e != nil || !v.Accepted {
				done <- fmt.Errorf("posting %d: %+v %v", i, v, e)
				return
			}
		}
		done <- nil
	}()
	for i := range 8 {
		path, fields := metadataForm(t, c, board.ID)
		fields.Set("key", fmt.Sprint("renamed", i))
		fields.Set("name", fmt.Sprint("板", i))
		res, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 303 {
			t.Fatal("rename", res.StatusCode, body)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBoardMetadataFailedSaveKeepsPublishedValues(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "original", "元の板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	path, fields := metadataForm(t, c, board.ID)
	fields.Set("key", "renamed")
	fields.Set("name", "未保存")
	if err = repo.site.Close(); err != nil {
		t.Fatal(err)
	}
	res, _ := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 503 {
		t.Fatal("failed save", res.StatusCode)
	}
	if got := repo.posting[board.ID].metadata(); got.Key != "original" || got.Name != "元の板" {
		t.Fatal("published unsaved metadata", got)
	}
	c.server.Close()
	_ = repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.webBoard("original")
	if err != nil || got == nil || got.Key != "original" || got.Name != "元の板" {
		t.Fatal("failed save changed durable metadata", got, err)
	}
}

func TestBoardMetadataAliasesKeepHiddenBoardGate(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "original", "専ブラ板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	path, fields := metadataForm(t, c, board.ID)
	fields.Set("key", "renamed")
	res, _ := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode)
	}
	repo.posting[board.ID].hidden.Store(true)
	public, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"original", "renamed"} {
		for _, path := range []string{"/test/read.cgi/" + key + "/1/", "/web/post?bbs=" + key} {
			w := httptest.NewRecorder()
			public.Handler.ServeHTTP(w, httptest.NewRequest("GET", cfg.Public.BaseURL+path, nil))
			if w.Code != 403 {
				t.Fatal("hidden board bypass", path, w.Code)
			}
		}
	}
}

func TestAdminBoardMetadataCrash(t *testing.T) {
	if config := os.Getenv("OIMO_TEST_METADATA_CONFIG"); config != "" {
		cfg, err := LoadConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		repo, err := openPostingRepository(cfg, func(point string) {
			if point == os.Getenv("OIMO_TEST_METADATA_STOP") {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		}, postcapture.Validate)
		if err != nil {
			t.Fatal(err)
		}
		boards, err := repo.Boards()
		if err != nil || len(boards) != 1 {
			t.Fatal(boards, err)
		}
		c := newAdminClient(t, repo)
		if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
			t.Fatal("authentication")
		}
		path, fields := metadataForm(t, c, boards[0].ID)
		fields.Set("key", "renamed")
		fields.Set("name", "変更済み")
		c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		t.Fatal("child did not stop")
	}
	for _, point := range []string{"board_metadata_prepared", "board_metadata_durable"} {
		t.Run(point, func(t *testing.T) {
			cfg, repo := adminFixture(t)
			board, err := repo.CreateBoard(t.Context(), "original", "元の板")
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.Close(); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(cfg)
			config := filepath.Join(filepath.Dir(cfg.DataDir), "metadata-crash.json")
			mustWrite(t, config, raw)
			cmd := exec.Command(os.Args[0], "-test.run=^TestAdminBoardMetadataCrash$")
			cmd.Env = append(os.Environ(), "OIMO_TEST_METADATA_CONFIG="+config, "OIMO_TEST_METADATA_STOP="+point)
			out, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("child %v: %s", err, out)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("not SIGKILL: %v %s", err, out)
			}
			repo, err = OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal("reopen", err)
			}
			defer repo.Close()
			got, err := repo.webBoard("original")
			if err != nil || got == nil || got.ID != board.ID {
				t.Fatal(got, err)
			}
			key, name := "original", "元の板"
			if point == "board_metadata_durable" {
				key, name = "renamed", "変更済み"
			}
			if got.Key != key || got.Name != name {
				t.Fatal("partial metadata update", got)
			}
		})
	}
}
