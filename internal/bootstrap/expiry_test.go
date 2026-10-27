// 永続期限失効の停止点・時計逆行・本文WAL不変・送信側引渡しを検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func TestPersistentExpiryRecovery(t *testing.T) {
	for _, stop := range []string{"", "lease", "shutdown", "expiry:intent", "expiry:public_stopped", "expiry:applied"} {
		t.Run(stop, func(t *testing.T) {
			cfg, repo := adminFixture(t)
			defer func() { _ = repo.Close() }()
			if e := repo.EnableThreadRetention(context.Background()); e != nil {
				t.Fatal(e)
			}
			info, e := repo.CreateBoard(context.Background(), "expiry", "期限")
			if e != nil {
				t.Fatal(e)
			}
			form := formServer(t, repo, siteID(repo.site.State()), info.ID)
			defer form.Close()
			created, e := sendForm(form, url.Values{"bbs": {"expiry"}, "subject": {"expiry-title"}, "MESSAGE": {"expiry-private-body"}, "oimo_request_id": {"expiry-create-0001"}})
			if e != nil || !created.Accepted {
				t.Fatal(created, e)
			}
			snapshot, e := repo.Thread(context.Background(), info.ID, created.Key)
			if e != nil || snapshot == nil {
				t.Fatal(snapshot, e)
			}
			wal := filepath.Join(cfg.DataDir, "boards", info.ID.String(), "threads", fmt.Sprint(created.Key), "delta-000001.wal")
			before, e := os.ReadFile(wal)
			if e != nil {
				t.Fatal(e)
			}
			b := repo.posting[info.ID]
			if stop == "lease" || stop == "shutdown" {
				if _, e := snapshot.AcquirePublic(snapshot.Expires, nil); !errors.Is(e, app.ErrPublicationGone) {
					t.Fatal("send expiry", e)
				}
			}
			if stop != "shutdown" {
				_, e = b.worker.Submit(context.Background(), func() (any, error) {
					if stop != "lease" {
						b.clock = func() time.Time { return time.Unix(0, int64(snapshot.Expires)) }
					}
					b.deletionCheckpoint = func(stage string) error {
						if stage == stop {
							return errors.New("simulated shutdown")
						}
						return nil
					}
					return b.scanExpiry(true)
				})
			}
			if (e != nil) != (stop != "" && stop != "lease" && stop != "shutdown") {
				t.Fatal("checkpoint", e)
			}
			if _, e := snapshot.AcquirePublic(snapshot.Expires-1, nil); !errors.Is(e, app.ErrPublicationGone) {
				t.Fatal("old lease revived", e)
			}
			form.Close()
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			got, e := repo.Thread(context.Background(), info.ID, created.Key)
			if e != nil || got != nil {
				t.Fatal("restart clock rollback revived body", got, e)
			}
			after, e := os.ReadFile(wal)
			if e != nil || string(before) != string(after) {
				t.Fatal("expiry appended body WAL", e)
			}
			b = repo.posting[info.ID]
			_, e = b.worker.Submit(context.Background(), func() (any, error) {
				log := b.deletions[created.Key]
				if log == nil || log.State().Seq != 3 || len(log.State().Rows) != 1 {
					return nil, errors.New("duplicate expiry")
				}
				for _, row := range log.State().Rows {
					var v DeletionRecord
					if e := strictjson.Decode(row.Value, &v); e != nil {
						return nil, e
					}
					if v.Kind != "expire" || v.Phase != "applied" || v.TargetSeq != nil || v.Expected != 1 || v.CleanupDue != snapshot.Expires+300e9 {
						return nil, fmt.Errorf("unexpected expiry record: %+v", v)
					}
					if strings.Contains(string(row.Value), "expiry-title") || strings.Contains(string(row.Value), "expiry-private-body") {
						return nil, errors.New("private ledger")
					}
				}
				return b.scanExpiry(true)
			})
			if e != nil {
				t.Fatal(e)
			}
			admin := newAdminClient(t, repo)
			defer admin.server.Close()
			if admin.login(adminTestSecret) != 303 {
				t.Fatal("login")
			}
			path := fmt.Sprintf("/boards/%s/threads/%d/moderation", info.ID, created.Key)
			res, body := admin.request("GET", path, "", nil)
			if res.StatusCode != 200 || !strings.Contains(body, "保持期限終了") || strings.Contains(body, `name="kind"`) {
				t.Fatal(res.StatusCode, body)
			}
			res, body = admin.request("GET", "/api/v1"+path, "", nil)
			if res.StatusCode != 200 || !strings.Contains(body, `"kind":"expire"`) {
				t.Fatal(res.StatusCode, body)
			}
		})
	}
}

func TestExpiryValidation(t *testing.T) {
	v := DeletionRecord{ID: domain.NewID(), Board: domain.NewID(), Thread: 1, Kind: "expire", Ranges: []app.RedactionRange{}, Expected: 1, TargetOperation: domain.NewID(), Format: 1, Phase: "intent", Created: 500e9, Expires: 500e9, CleanupDue: 800e9, Actor: domain.Actor{Kind: "system", Reason: "thread_expire"}, Versions: domain.Versions{Site: 1, Board: 1, Thread: 1}, Audit: "pending"}
	encode := func(v DeletionRecord) []byte { raw, _ := json.Marshal(v); return raw }
	if e := validateDeletion("deletion", v.ID.String(), nil, encode(v)); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*DeletionRecord){
		func(v *DeletionRecord) { seq := domain.U64(2); v.TargetSeq = &seq },
		func(v *DeletionRecord) { v.Created-- },
		func(v *DeletionRecord) { v.CleanupDue++ },
		func(v *DeletionRecord) { v.HideTitle = true },
		func(v *DeletionRecord) { v.Actor.Reason = "thread_moderation" },
		func(v *DeletionRecord) { v.Ranges = []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}} },
	} {
		bad := v
		change(&bad)
		if e := validateDeletion("deletion", bad.ID.String(), nil, encode(bad)); e == nil {
			t.Fatal("invalid expiry accepted", bad)
		}
	}
}
