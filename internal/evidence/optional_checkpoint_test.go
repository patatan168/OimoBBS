// 全日回収のcheckpoint設置境界と候補復旧を実fileで確認する。
package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOptionalCheckpointRecovery(t *testing.T) {
	for _, state := range []string{"canonical", "complete_tmp", "partial_tmp", "different_tmp", "unknown_day_file", "partly_removed"} {
		t.Run(state, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			root := t.TempDir()
			os.Chmod(root, 0700)
			site := domain.NewID()
			s, e := OpenOptionalStore(root, site, key)
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now()
			r := optionalFixture()
			r.Site = site
			r.Received = domain.Time(now.Add(-OptionalRetention + time.Minute).UnixNano())
			r.Finished = r.Received + 100
			r.Until = r.Received + domain.Time(OptionalRetention)
			if e = s.Write(context.Background(), r); e != nil {
				t.Fatal(e)
			}
			day := time.Unix(0, int64(r.Received)).UTC().Format("20060102")
			dir := filepath.Join(root, day)
			s.checkpoint = func(at string) error {
				if at == "optional:checkpoint_saved" {
					return store.ErrIncomplete
				}
				return nil
			}
			if _, e = s.Sweep(now.Add(2 * time.Minute)); e == nil {
				t.Fatal("checkpoint stop ignored")
			}
			s.Close()
			canonical := filepath.Join(root, day+".checkpoint.json")
			raw, e := os.ReadFile(canonical)
			if e != nil {
				t.Fatal(e)
			}
			var candidate []byte
			if state == "complete_tmp" || state == "partial_tmp" || state == "different_tmp" {
				candidate = raw
				if state == "partial_tmp" {
					candidate = raw[:40]
				}
				if state == "different_tmp" {
					candidate = []byte("different candidate")
				} else if e = os.Remove(canonical); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(canonical+".tmp", candidate, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if state == "unknown_day_file" {
				if e = os.WriteFile(filepath.Join(dir, "unknown"), []byte("keep"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if state == "partly_removed" {
				if e = os.Remove(filepath.Join(dir, "control.current")); e != nil {
					t.Fatal(e)
				}
			}
			if e = InspectOptionalStore(root, site, key); e == nil {
				t.Fatal("read-only allowed unfinished cleanup")
			}
			if state == "complete_tmp" || state == "partial_tmp" || state == "different_tmp" {
				saved, _ := os.ReadFile(canonical + ".tmp")
				if !bytes.Equal(saved, candidate) {
					t.Fatal("inspection changed candidate")
				}
			}
			s, e = OpenOptionalStore(root, site, key)
			if state == "different_tmp" || state == "unknown_day_file" {
				if e == nil {
					s.Close()
					t.Fatal("unknown/different artifact was deleted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if state == "partial_tmp" {
				if len(s.journals) != 1 {
					t.Fatal("incomplete checkpoint deleted original")
				}
				if _, e = s.Sweep(now.Add(2 * time.Minute)); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = os.Stat(dir); !os.IsNotExist(e) {
				t.Fatal("expired day remained", e)
			}
			if e = InspectOptionalStore(root, site, key); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestOptionalInspectDoesNotRepairPartialWAL(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	os.Chmod(root, 0700)
	site := domain.NewID()
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	r := optionalFixture()
	r.Site = site
	r.Received = domain.Time(time.Now().UnixNano())
	r.Finished = r.Received + 100
	r.Until = r.Received + domain.Time(OptionalRetention)
	if e = s.Write(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	s.Close()
	day := time.Unix(0, int64(r.Received)).UTC().Format("20060102")
	wal := filepath.Join(root, day, "control-000001.wal")
	original, e := os.ReadFile(wal)
	if e != nil {
		t.Fatal(e)
	}
	changed := append(bytes.Clone(original), 1, 2, 3)
	if e = os.WriteFile(wal, changed, 0600); e != nil {
		t.Fatal(e)
	}
	if e = InspectOptionalStore(root, site, key); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal(e)
	}
	saved, e := os.ReadFile(wal)
	if e != nil || !bytes.Equal(saved, changed) {
		t.Fatal("read-only truncated WAL", e)
	}
	s, e = OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = InspectOptionalStore(root, site, key); e != nil {
		t.Fatal(e)
	}
}
