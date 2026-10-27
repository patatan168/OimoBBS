// 管理変更の確定順・削除行・旧差分無効化と、署名journalからの再起動を確認する。
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func TestModerationDurability(t *testing.T) {
	for _, kind := range []string{"redact", "hide"} {
		for _, stop := range []string{"", "proposal", "thread", "decision"} {
			t.Run(kind+"/"+stop, func(t *testing.T) {
				owner, create, now := postingFixture(t)
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				root := t.TempDir()
				if e := os.Chmod(root, 0700); e != nil {
					t.Fatal(e)
				}
				parent := filepath.Join(root, "threads")
				if e := os.Mkdir(parent, 0700); e != nil {
					t.Fatal(e)
				}
				open := func() (*PostingLog, *evidence.Journal) {
					j, e := evidence.OpenJournal(filepath.Join(root, "20231114"), owner, 20231114, 10, key, PostingValidator(fixtureCapture))
					if e != nil {
						t.Fatal(e)
					}
					p, e := OpenPosting(parent, owner, 1700000000, []*evidence.Journal{j}, j, now)
					if e != nil {
						t.Fatal(e)
					}
					return p, j
				}
				p, j := open()
				if r := p.Post(context.Background(), create, []byte(`{"fixture":true}`), now); r.Status != store.Durable {
					t.Fatal(r)
				}
				id, h, k := domain.NewID(), domain.Hash{1}, uint32(8)
				input := ModerationInput{ID: domain.NewID(), DeletionID: domain.NewID(), Type: kind, Expected: 1, Actor: domain.Actor{Kind: "admin", ID: &id, Reason: "moderation", Request: &h, Idempotency: &h, KeyID: &k}, Versions: domain.Versions{Site: 1, Board: 1}, Now: now}
				if kind == "redact" {
					input.Ranges = []RedactionRange{{1, 1, "aboon"}}
				}
				frame, e := p.PrepareModeration(input)
				if e != nil {
					t.Fatal(e)
				}
				p.checkpoint = func(stage string) error {
					if stage == stop {
						return errors.New("stop")
					}
					return nil
				}
				result := p.ApplyModeration(context.Background(), frame, now)
				if stop == "" && result.Status != store.Durable || stop != "" && result.Status != store.Unknown {
					t.Fatal(result)
				}
				p.Close()
				j.Close()
				p, j = open()
				defer p.Close()
				defer j.Close()
				snap := p.Snapshot(now)
				if stop == "proposal" {
					if snap == nil || snap.Revision != 1 {
						t.Fatal("unwritten moderation applied")
					}
					if result := p.ApplyModeration(context.Background(), frame, now); result.Status != store.Durable {
						t.Fatal("fixed proposal did not resume", result)
					}
					proposals := 0
					for _, entry := range j.Entries() {
						if entry.Event.Kind == "thread_admin_proposal" {
							proposals++
						}
					}
					if proposals != 1 {
						t.Fatal("resume duplicated proposal", proposals)
					}
					snap = p.Snapshot(now)
				}
				if kind == "hide" {
					if snap != nil {
						t.Fatal("hidden thread published")
					}
					return
				}
				if snap == nil || snap.Revision != 2 || !snap.LegacyRangeDisabled || p.thread.State().Posts[0].Body != "あぼーん" {
					t.Fatal(snap)
				}
			})
		}
	}
}
