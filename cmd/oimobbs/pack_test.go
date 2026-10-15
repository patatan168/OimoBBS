// pack CLIを実HTTPで作成した投稿へ適用し、停止中排他・再実行・旧世代回収を検証する。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackCLI(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "data"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:8080", BaseURL: "http://127.0.0.1:8080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:8081", Origin: "http://127.0.0.1:8081", Transport: "loopback_tunnel"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	site, e := bootstrap.Initialize(cfg, "pack CLI")
	if e != nil {
		t.Fatal(e)
	}
	r, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.ConfigureAdministrator("owner", "所有者", "pack-cli-test-password", false); e != nil {
		t.Fatal(e)
	}
	_ = r.Close()
	r, e = bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	board, e := r.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	observer, e := evidence.NewHTTPObserver(site.SiteID, domain.NewID(), "pack-cli-test")
	if e != nil {
		t.Fatal(e)
	}
	type formResult struct {
		ThreadKey uint64
		Status    store.CommitStatus
		Token     string
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		result := r.SubmitLegacyRequest(req, board.ID, observer)
		token := ""
		if result.Confirmation != nil {
			token = result.Confirmation.Token
		}
		if e := json.NewEncoder(w).Encode(formResult{result.ThreadKey, result.Status, token}); e != nil {
			t.Error(e)
		}
	}))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	fields := url.Values{"bbs": {"news"}, "subject": {"title"}, "MESSAGE": {"body"}}
	var posted formResult
	token := ""
	for range 2 {
		req, e := http.NewRequest("POST", server.URL+"/test/bbs.cgi", strings.NewReader(fields.Encode()))
		if e != nil {
			t.Fatal(e)
		}
		req.Host = "127.0.0.1:8080"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		if token != "" {
			req.AddCookie(&http.Cookie{Name: "oimo_confirm", Value: token})
		}
		response, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		posted = formResult{}
		e = json.NewDecoder(response.Body).Decode(&posted)
		_ = response.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		token = posted.Token
	}
	server.Close()
	if posted.Status != store.Durable || posted.ThreadKey == 0 {
		t.Fatal(posted)
	}
	raw, _ := json.Marshal(cfg)
	config := filepath.Join(parent, "config.json")
	if e = os.WriteFile(config, raw, 0600); e != nil {
		t.Fatal(e)
	}
	args := []string{"pack", "compact", "--config", config, "--board", board.ID.String(), "--thread", fmt.Sprint(posted.ThreadKey)}
	var out, diag bytes.Buffer
	if e = run(args, &out, &diag); e == nil || out.Len() != 0 {
		t.Fatal("live lock bypassed")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	for _, a := range [][]string{{"pack"}, {"pack", "compact"}, {"pack", "compact", "--board", board.ID.String(), "--thread", "0"}, append(append([]string{}, args...), "--level", "2"), append(append([]string{}, args...), "--apply")} {
		out.Reset()
		if e = run(a, &out, &diag); e == nil || out.Len() != 0 {
			t.Fatal("invalid success", a, e)
		}
	}
	for _, a := range [][]string{args, {"pack", "enable", "--config", config}, {"pack", "enable", "--config", config}, append(append([]string{}, args...), "--apply")} {
		out.Reset()
		if e = run(a, &out, &diag); e != nil {
			t.Fatal(a, e)
		}
	}
	for _, apply := range []bool{false, true} {
		a := []string{"pack", "maintain", "--config", config, "--limit", "1"}
		if apply {
			a = append(a, "--apply")
		}
		out.Reset()
		if e = run(a, &out, &diag); e != nil {
			t.Fatal(e)
		}
		var report bootstrap.PackMaintenanceReport
		if e = json.Unmarshal(out.Bytes(), &report); e != nil || len(report.Entries) != 1 || report.Applied != apply {
			t.Fatal(report, e)
		}
		if !apply && report.Entries[0].Reclaim.Files != 1 {
			t.Fatal(report)
		}
	}
	args[1] = "reclaim"
	for _, apply := range []bool{false, true, true} {
		a := append([]string{}, args...)
		if apply {
			a = append(a, "--apply")
		}
		out.Reset()
		if e = run(a, &out, &diag); e != nil {
			t.Fatal(e)
		}
		var report store.ThreadReclaimReport
		if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Applied != apply {
			t.Fatal(report, e)
		}
	}
	r, e = bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	snapshot, e := r.Thread(context.Background(), board.ID, posted.ThreadKey)
	if e != nil || snapshot == nil || snapshot.PostCount != 1 {
		t.Fatal(snapshot, e)
	}
}
