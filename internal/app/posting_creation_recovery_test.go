// 未決定の作成WALを署名要求で照合し、参照補完・再送・再起動の一意性を検査する。
package app

import (
	"context"
	"errors"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestPostingCreationRecovery(t *testing.T) {
	for _, scenario := range []string{"complete", "short", "changed", "not_accepted"} {
		t.Run(scenario, func(t *testing.T) {
			p, j, frame, now, _, _ := newPostingTest(t)
			p.checkpoint = func(stage string) error {
				if stage == "proposal" {
					return errors.New("stop before creation")
				}
				return nil
			}
			if r := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); r.Status != store.Unknown {
				t.Fatal(r)
			}
			if scenario == "not_accepted" {
				for _, entry := range p.proposals {
					if r := p.decide(entry, "not_accepted", true, now); r.Status != store.Durable {
						t.Fatal(r)
					}
				}
			}
			log, err := store.CreateThread(p.parent, p.owner, p.key, frame)
			if err != nil {
				t.Fatal(err)
			}
			if err = log.Close(); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(p.parent, "1700000000")
			if err = os.Remove(filepath.Join(dir, "current.json")); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "delta-000001.wal")
			if scenario == "short" || scenario == "changed" {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "short" {
					raw = raw[:len(raw)-1]
				} else {
					raw[len(raw)-1] ^= 1
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := len(j.Entries())
			opened, err := OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, now)
			if scenario != "complete" {
				if !errors.Is(err, ErrEvidenceGap) || opened != nil || len(j.Entries()) != before {
					t.Fatal("unsafe recovery", err)
				}
				if _, err = os.Lstat(filepath.Join(dir, "current.json")); !os.IsNotExist(err) {
					t.Fatal("rejection changed current", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opened.Snapshot(now) == nil || opened.Snapshot(now).PostCount != 1 || len(j.Entries()) != before+1 {
				t.Fatal("recovery not published once")
			}
			if r := opened.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); r.Status != store.Durable || !r.Duplicate {
				t.Fatal(r)
			}
			if err = opened.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err = OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, now)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			if len(j.Entries()) != before+1 {
				t.Fatal("repeated recovery appended decision")
			}
		})
	}
}
