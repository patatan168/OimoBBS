// 公開本体の実回収と各停止点の復旧で、再公開・再作成・受理枠喪失を拒否する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func hideBodyFixture(t *testing.T, repo *Repository, board domain.ID, key uint64) {
	t.Helper()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board, key)
	res, _ := client.request("GET", path, "", nil)
	raw, _ := json.Marshal(AdminModeration{Kind: "hide", Ranges: []app.RedactionRange{}})
	res, body := client.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"body-hide-request-0001"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
}

func TestPublicBodyReclamationRecovery(t *testing.T) {
	stages := []string{"", "reclaim:watermark", "reclaim:proof", "reclaim:carry_page", "reclaim:carry_seal", "reclaim:cleaning", "reclaim:running", "reclaim:file", "reclaim:files_synced", "reclaim:parent_synced", "reclaim:complete"}
	for _, kind := range []string{"hide", "expire"} {
		for _, stage := range stages {
			t.Run(kind+"/"+stage, func(t *testing.T) {
				ctx := context.Background()
				cfg, repo := adminFixture(t)
				defer func() {
					if repo != nil {
						_ = repo.Close()
					}
				}()
				board, e := repo.CreateBoard(ctx, "body", "本体回収")
				if e != nil {
					t.Fatal(e)
				}
				if e = repo.EnablePublicBodyReclamation(ctx); e != nil {
					t.Fatal(e)
				}
				form := formServer(t, repo, siteID(repo.site.State()), board.ID)
				create := url.Values{"bbs": {"body"}, "subject": {"unpublished-sensitive-title"}, "MESSAGE": {"unpublished-sensitive-body"}, "oimo_request_id": {"body-create-request-0001"}}
				created, e := sendForm(form, create)
				if e != nil || !created.Accepted {
					t.Fatal(created, e)
				}
				snapshot, e := repo.Thread(ctx, board.ID, created.Key)
				if e != nil || snapshot == nil {
					t.Fatal(snapshot, e)
				}
				before, e := repo.rateHistory()
				if e != nil || len(before) != 1 {
					t.Fatal(before, e)
				}
				// 現行packと旧WALを含む全公開世代を回収する。
				if _, e = repo.EnablePostingPacks(ctx); e != nil {
					t.Fatal(e)
				}
				if _, e = repo.CompactThread(ctx, board.ID, created.Key, 6, true); e != nil {
					t.Fatal(e)
				}
				if kind == "hide" {
					hideBodyFixture(t, repo, board.ID, created.Key)
				}
				b := repo.posting[board.ID]
				_, e = b.worker.Submit(ctx, func() (any, error) {
					if kind == "expire" {
						b.clock = func() time.Time { return time.Unix(0, int64(snapshot.Expires)) }
						defer func() { b.clock = time.Now }()
						if _, e := b.scanExpiry(true); e != nil {
							return nil, e
						}
					}
					b.deletionCheckpoint = func(s string) error {
						if stage != "" && stage == s {
							return errors.New("simulated crash")
						}
						return nil
					}
					return nil, b.cleanPublicBodies(1)
				})
				if (e != nil) != (stage != "") {
					t.Fatal(stage, e)
				}
				form.Close()
				if e = repo.Close(); e != nil {
					t.Fatal(e)
				}
				repo, e = OpenPostingRepository(cfg, postcapture.Validate)
				if e != nil {
					t.Fatal("resume", e)
				}
				restored := repo.posting[board.ID]
				proofs, e := restored.bodyReclamations()
				if e != nil {
					t.Fatal(e)
				}
				carry, e := readBodyCarry(restored.deletions[created.Key].State(), proofs[created.Key])
				if e != nil || carry == nil || len(carry.Rates) != 1 {
					t.Fatal("clock rollback lost durable rate carry", e)
				}

				dir := filepath.Join(cfg.DataDir, "boards", board.ID.String(), "threads", fmt.Sprint(created.Key))
				if _, e = os.Lstat(dir); !os.IsNotExist(e) {
					t.Fatal("public body retained", e)
				}
				got, e := repo.Thread(ctx, board.ID, created.Key)
				if e != nil || got != nil {
					t.Fatal("body republished", got, e)
				}
				after, e := repo.rateHistory()
				if e != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("quota history changed", after, e)
				}
				b = repo.posting[board.ID]
				proof, e := readBodyReclamation(b.deletions[created.Key].State(), board.ID, created.Key, b.key.Public().(ed25519.PublicKey))
				if e != nil || proof == nil || proof.Kind != kind {
					t.Fatal(proof, e)
				}
				form = formServer(t, repo, siteID(repo.site.State()), board.ID)
				beforeSeq := b.control.State().Seq
				retry, e := sendForm(form, create)
				form.Close()
				if e != nil || retry.Accepted || b.control.State().Seq != beforeSeq {
					t.Fatal("recreated reclaimed thread", retry, e)
				}
				for name, row := range b.deletions[created.Key].State().Rows {
					if strings.Contains(string(row.Value), "unpublished-sensitive") || strings.Contains(string(row.Value), "127.0.0.1") {
						t.Fatal("private data in ledger", name)
					}
					if strings.HasPrefix(name, "copy_task:") {
						var task DeletionCopyTask
						if strictjson.Decode(row.Value, &task) != nil || task.Kind != "live" || task.State != "complete" {
							t.Fatal(task)
						}
					}
				}
				var water struct {
					Last domain.U64 `json:"last_removed_bump"`
				}
				if strictjson.Decode(b.control.State().Rows["bump_watermark:ranking"].Value, &water) != nil || water.Last == 0 {
					t.Fatal("ranking watermark lost")
				}
			})
		}
	}
}
