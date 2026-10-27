// 認証済みsnapshotを実Repositoryで再起動し、監査索引・投稿・管理更新の継続を検証する。
package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// installRuntimeFixture は停止した試験用保存先だけを切り替える。運用CLIの代用ではない。
func installRuntimeFixture(t *testing.T, cfg Config, r *Repository, minimum uint32) controlCandidate {
	t.Helper()
	func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		var site siteState
		if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
			t.Fatal(err)
		}
		site.MinimumReader = max(site.MinimumReader, minimum)
		if err := appendControl(r.site, "snapshot_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); err != nil {
			t.Fatal(err)
		}
	}()
	importCandidateAudit(t, r)
	dir := filepath.Join(candidateParent(t), "candidate")
	if _, err := r.PrepareControlSnapshot(context.Background(), dir, 6); err != nil {
		t.Fatal(err)
	}
	m, err := readCandidateManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, item := range m.Owners {
		path := controlOwnerPath(cfg.DataDir, item.Kind, item.Owner)
		raw, err := os.ReadFile(filepath.Join(dir, anchorFile(item)))
		if err != nil {
			t.Fatal(err)
		}
		if err = writeNew(filepath.Join(path, fmt.Sprintf("control-%06d.anchor.json", item.Generation)), raw); err != nil {
			t.Fatal(err)
		}
		apply := store.ValueValidator(validateSiteValue)
		if item.Kind == "board" {
			apply = validateBoardValue
		}
		log, err := store.OpenControlWithValidators(path, item.header().Kind, item.Owner, 0, apply, snapshotValues(item.Kind))
		if err != nil {
			t.Fatal(err)
		}
		raw, err = os.ReadFile(filepath.Join(dir, item.File))
		if err != nil {
			log.Close()
			t.Fatal(err)
		}
		result := log.SwitchSnapshot(raw)
		log.Close()
		if result.Status != store.Durable {
			t.Fatal(result)
		}
		if err = os.Remove(filepath.Join(path, "control-000001.wal")); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestSnapshotRepositoryAuditAndPosting(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() {
		if r != nil {
			r.Close()
		}
	}()
	ctx := context.Background()
	board, err := r.CreateBoard(ctx, "snaptest", "再起動試験")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, r, siteID(r.site.State()), board.ID)
	request := url.Values{"bbs": {"snaptest"}, "subject": {"元スレッド"}, "MESSAGE": {"元の投稿"}, "oimo_request_id": {"snapshot-create-request-001"}}
	first, err := sendForm(form, request)
	form.Close()
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	q := auditQuery{From: time.Now().Add(-24 * time.Hour), To: time.Now().Add(time.Second), Limit: 200}
	before, err := collectAuditFixture(r, ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	m := installRuntimeFixture(t, cfg, r, 12)
	r = nil
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	after, err := collectAuditFixture(r, ctx, q)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("audit restored", len(before), len(after), err)
	}
	proof, err := r.VerifyAuditTransfer(ctx)
	if err != nil || !proof.Complete {
		t.Fatal(proof, err)
	}
	if _, err = r.Boards(); err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, r)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login after snapshot")
	}
	res, site := client.site()
	res, body := client.request("PATCH", "/api/v1/site", `{"name":"snapshot後のサイト"}`, candidateHeaders(res.Header.Get("ETag"), res.Header.Get("X-CSRF-Token")))
	client.server.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatal(site, body)
	}
	form = formServer(t, r, m.Site, board.ID)
	duplicate, err := sendForm(form, request)
	if err != nil || !duplicate.Duplicate || duplicate.Key != first.Key {
		form.Close()
		t.Fatal(duplicate, err)
	}
	request.Set("oimo_request_id", "snapshot-create-request-002")
	request.Set("subject", "新規スレッド")
	created, err := sendForm(form, request)
	form.Close()
	if err != nil || !created.Accepted || created.Key <= first.Key {
		t.Fatal(created, err)
	}
	proof, err = r.VerifyAuditTransfer(ctx)
	if err != nil || proof.Complete {
		t.Fatal("unimported delta", proof, err)
	}
	r.Close()
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart before audit catchup", err)
	}
	q.To = time.Now().Add(time.Second)
	latest, err := collectAuditFixture(r, ctx, q)
	if err != nil || len(latest) <= len(after) {
		t.Fatal("delta index", len(latest), err)
	}
	proof, err = r.VerifyAuditTransfer(ctx)
	if err != nil || !proof.Complete {
		t.Fatal(proof, err)
	}
	r.Close()
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	again, err := collectAuditFixture(r, ctx, q)
	if err != nil || !reflect.DeepEqual(latest, again) {
		t.Fatal("second restart", err)
	}
	// snapshot所有者と新規の第1世代所有者を混在させる。
	if _, err = r.CreateBoard(ctx, "nextboard", "追加板"); err != nil {
		t.Fatal(err)
	}
	importCandidateAudit(t, r)
	r.Close()
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("mixed generations", err)
	}
	proof, err = r.VerifyAuditTransfer(ctx)
	if err != nil || !proof.Complete {
		t.Fatal(proof, err)
	}
}

func TestSnapshotRepositoryRejectsIncompleteBoundary(t *testing.T) {
	for _, bad := range []string{"reader", "pending", "anchor", "archive"} {
		t.Run(bad, func(t *testing.T) {
			cfg, r := adminFixture(t)
			minimum := uint32(12)
			if bad == "reader" {
				minimum = 11
			}
			m := installRuntimeFixture(t, cfg, r, minimum)
			path := filepath.Join(cfg.DataDir, "site")
			switch bad {
			case "pending":
				if err := os.WriteFile(filepath.Join(path, "control-000003.wal"), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			case "anchor":
				if err := os.Remove(filepath.Join(path, "control-000002.anchor.json")); err != nil {
					t.Fatal(err)
				}
			case "archive":
				if err := os.RemoveAll(filepath.Join(cfg.DataDir, "audit", m.Site.String())); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := OpenPostingRepository(cfg, postcapture.Validate)
			if err == nil {
				opened.Close()
				t.Fatal("invalid snapshot repository accepted")
			}
		})
	}
}
