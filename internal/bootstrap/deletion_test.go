// 管理HTTPと停止点からの復旧で、旧本文の非公開と同一操作の再開を確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeletionHTTPAndRecovery(t *testing.T) {
	for _, kind := range []string{"redact", "hide"} {
		for _, stop := range []string{"", "deletion:intent", "deletion:public_stopped", "deletion:thread", "deletion:applied"} {
			t.Run(kind+"/"+stop, func(t *testing.T) {
				cfg, repo := adminFixture(t)
				defer func() { repo.Close() }()
				info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
				if e != nil {
					t.Fatal(e)
				}
				client := newAdminClient(t, repo)
				defer func() { client.server.Close() }()
				if client.login(adminTestSecret) != 303 {
					t.Fatal("login")
				}
				form := formServer(t, repo, siteID(repo.site.State()), info.ID)
				defer func() { form.Close() }()
				create := url.Values{"bbs": {"news"}, "subject": {"title"}, "MESSAGE": {"original-private-body"}, "oimo_request_id": {"deletion-create-0001"}}
				accepted, e := sendForm(form, create)
				if e != nil || !accepted.Accepted {
					t.Fatal(accepted, e)
				}
				path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", info.ID, accepted.Key)
				res, _ := client.request("GET", path, "", nil)
				if res.StatusCode != 200 {
					t.Fatal(res.StatusCode)
				}
				headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"moderation-request-0001"}}
				edit := AdminModeration{Kind: kind, Ranges: []app.RedactionRange{}}
				if kind == "redact" {
					edit.Ranges = []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}
				}
				raw, _ := json.Marshal(edit)
				if stop == "" {
					missing := headers.Clone()
					missing.Del("If-Match")
					res, body := client.request("POST", path, string(raw), missing)
					if res.StatusCode != 428 {
						t.Fatal("missing revision", res.StatusCode, body)
					}
				}
				if stop != "" {
					repo.posting[info.ID].deletionCheckpoint = func(stage string) error {
						if stage == stop {
							return errors.New("simulated shutdown")
						}
						return nil
					}
				}
				res, body := client.request("POST", path, string(raw), headers)
				if stop == "" {
					if res.StatusCode != 200 || !strings.Contains(body, `"cleanup_complete":false`) {
						t.Fatal(res.StatusCode, body)
					}
				} else if res.StatusCode != 503 {
					t.Fatal("checkpoint", res.StatusCode, body)
				}

				form.Close()
				client.server.Close()
				if e = repo.Close(); e != nil {
					t.Fatal(e)
				}
				if stop == "" {
					wal := filepath.Join(cfg.DataDir, "expiry", info.ID.String(), fmt.Sprint(accepted.Key), "control-000001.wal")
					file, e := os.OpenFile(wal, os.O_WRONLY|os.O_APPEND, 0600)
					if e != nil {
						t.Fatal(e)
					}
					if _, e = file.Write([]byte{1, 2, 3}); e != nil {
						t.Fatal(e)
					}
					if e = file.Sync(); e != nil {
						t.Fatal(e)
					}
					if e = file.Close(); e != nil {
						t.Fatal(e)
					}
				}
				repo, e = OpenPostingRepository(cfg, postcapture.Validate)
				if e != nil {
					t.Fatal(e)
				}
				snap, e := repo.Thread(context.Background(), info.ID, accepted.Key)
				if e != nil {
					t.Fatal(e)
				}
				if kind == "hide" {
					if snap != nil {
						t.Fatal("hidden body republished")
					}
				} else {
					if snap == nil || snap.Revision != 2 || strings.Contains(string(snap.DAT), "original-private-body") || !snap.LegacyRangeDisabled {
						t.Fatal(snap)
					}
				}
				client = newAdminClient(t, repo)
				if client.login(adminTestSecret) != 303 {
					t.Fatal("relogin")
				}
				res, _ = client.request("GET", path, "", nil)
				headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
				res, _ = client.request("POST", path, string(raw), headers)
				if res.StatusCode != 200 {
					t.Fatal("idempotent resume", res.StatusCode)
				}
				form = formServer(t, repo, siteID(repo.site.State()), info.ID)
				retry, e := sendForm(form, create)
				if e != nil {
					t.Fatal(e)
				}
				if retry.Accepted {
					t.Fatal("deleted create retried successfully")
				}
				if stop == "" {
					form.Close()
					client.server.Close()
					if e = repo.Close(); e != nil {
						t.Fatal(e)
					}
					unknown := filepath.Join(cfg.DataDir, "expiry", info.ID.String(), fmt.Sprint(accepted.Key), "unknown")
					if e = writeNew(unknown, []byte("keep")); e != nil {
						t.Fatal(e)
					}
					opened, e := OpenPostingRepository(cfg, postcapture.Validate)
					if e == nil {
						opened.Close()
						t.Fatal("unknown deletion file accepted")
					}
					kept, e := os.ReadFile(unknown)
					if e != nil || string(kept) != "keep" {
						t.Fatal("unknown deletion file modified", e)
					}
					if e = os.Remove(unknown); e != nil {
						t.Fatal(e)
					}
					if e = os.Rename(filepath.Join(cfg.DataDir, "expiry", info.ID.String()), filepath.Join(t.TempDir(), "removed-ledger")); e != nil {
						t.Fatal(e)
					}
					opened, e = OpenPostingRepository(cfg, postcapture.Validate)
					if e == nil {
						opened.Close()
						t.Fatal("administrative evidence reopened without deletion ledger")
					}
					if !errors.Is(e, app.ErrEvidenceGap) {
						t.Fatal("unexpected missing ledger rejection", e)
					}
				}
			})
		}
	}
}

func TestOnlineBackupDeletionBoundary(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	form := formServer(t, r, siteID(r.site.State()), info.ID)
	defer form.Close()
	accepted, e := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"title"}, "MESSAGE": {"body"}, "oimo_request_id": {"backup-moderation-create"}})
	if e != nil || !accepted.Accepted {
		t.Fatal(accepted, e)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	route := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", info.ID, accepted.Key)
	moderate := func(title bool, id string) {
		res, _ := client.request("GET", route, "", nil)
		headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {id}}
		raw, _ := json.Marshal(AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}, HideTitle: title})
		res, body := client.request("POST", route, string(raw), headers)
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
	}
	moderate(false, "backup-redact-request-01")
	syncOnlineAudit(t, r)
	trust := onlineOutput(t, "trust.json")
	raw, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeNew(trust, raw); e != nil {
		t.Fatal(e)
	}
	body, keys := onlineOutput(t, "body"), onlineOutput(t, "keys")
	report, e := r.PrepareOnlineBackup(ctx, body, keys, filepath.Dir(onlineOutput(t, "work")), OnlineBackupPreparationOptions{TrustInstance: trust, PartialPlan: onlineOutput(t, "partial.json"), PartialKeysPlan: onlineOutput(t, "keys-partial.json"), PairPlan: onlineOutput(t, "pair.json")})
	if e != nil || !report.Complete {
		t.Fatal(report, e)
	}
	m, _, e := r.loadBackup(body)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, entry := range m.Entries {
		found = found || entry.Kind == "deletion"
	}
	if !found {
		t.Fatal("deletion ledger absent from backup")
	}
	changed := onlineOutput(t, "changed-body")
	_, e = r.captureOnlineBackup(ctx, changed, trust, onlineOutput(t, "changed-plan.json"), OnlineBackupSiteOptions{}, time.Now, func(stage string) error {
		if stage == "manifest_synced" {
			moderate(true, "backup-redact-request-02")
		}
		return nil
	})
	if !errors.Is(e, ErrOnlineBackupChanged) {
		t.Fatal("stale backup installed", e)
	}
	if _, e = os.Lstat(filepath.Join(changed, "manifest.json")); !os.IsNotExist(e) {
		t.Fatal("completion manifest survived invalidation", e)
	}
}

func TestDeletionRequestKeyExpiry(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	form := formServer(t, r, siteID(r.site.State()), info.ID)
	defer form.Close()
	accepted, e := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"title"}, "MESSAGE": {"body"}, "oimo_request_id": {"request-key-expiry-create"}})
	if e != nil || !accepted.Accepted {
		t.Fatal(accepted, e)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	route := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", info.ID, accepted.Key)
	res, _ := client.request("GET", route, "", nil)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"request-key-expiry-0001"}}
	raw, _ := json.Marshal(AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}})
	res, body := client.request("POST", route, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	var saved struct {
		Data DeletionRecord `json:"data"`
	}
	if e = json.Unmarshal([]byte(body), &saved); e != nil {
		t.Fatal(e)
	}
	res, _ = client.request("GET", route, "", nil)
	headers.Set("If-Match", res.Header.Get("ETag"))
	raw, _ = json.Marshal(AdminModeration{Kind: "hide", Ranges: []app.RedactionRange{}})
	b := r.posting[info.ID]
	b.clock = func() time.Time { return time.Unix(0, int64(saved.Data.Created)+int64(24*time.Hour)-1) }
	res, body = client.request("POST", route, string(raw), headers)
	if res.StatusCode != 409 {
		t.Fatal("unexpired key reused", res.StatusCode, body)
	}
	b.clock = func() time.Time { return time.Unix(0, int64(saved.Data.Created)+int64(24*time.Hour)) }
	res, body = client.request("POST", route, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("expired key not reusable", res.StatusCode, body)
	}
}
