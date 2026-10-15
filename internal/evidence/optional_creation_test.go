// 初回作成の保存境界と読取り専用検査を、同じ署名frameの再開で検証する。
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

func TestOptionalCreationResumeAndReadOnly(t *testing.T) {
	for _, stage := range []string{"optional:create_intent", "optional:create_control", "partial_wal", "duplicate_tmp", "complete_tmp"} {
		t.Run(stage, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			site := domain.NewID()
			s, e := OpenOptionalStore(root, site, key)
			if e != nil {
				t.Fatal(e)
			}
			stop := "optional:create_intent"
			if stage == "optional:create_control" || stage == "partial_wal" {
				stop = "optional:create_control"
			}
			s.checkpoint = func(at string) error {
				if at == stop {
					return store.ErrIncomplete
				}
				return nil
			}
			r := optionalFixture()
			r.Site = site
			r.Received = domain.Time(time.Now().UnixNano())
			r.Finished = r.Received + 100
			r.Until = r.Received + domain.Time(OptionalRetention)
			if e = s.Write(context.Background(), r); e == nil {
				t.Fatal("injected stop ignored")
			}
			s.Close()
			day := time.Unix(0, int64(r.Received)).UTC().Format("20060102")
			intent := filepath.Join(root, ".create-"+day+".frame")
			frame, e := os.ReadFile(intent)
			if e != nil {
				t.Fatal(e)
			}
			if stage == "partial_wal" {
				wal := filepath.Join(root, day, "control-000001.wal")
				original, err := os.ReadFile(wal)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(filepath.Join(root, day, "control.current")); err != nil {
					t.Fatal(err)
				}
				if e = os.WriteFile(wal, original[:40], 0600); e != nil {
					t.Fatal(e)
				}
			}
			if stage == "duplicate_tmp" || stage == "complete_tmp" {
				if e = os.WriteFile(intent+".tmp", frame, 0600); e != nil {
					t.Fatal(e)
				}
				if stage == "complete_tmp" {
					if e = os.Remove(intent); e != nil {
						t.Fatal(e)
					}
				}
			}
			if e = InspectOptionalStore(root, site, key); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("read-only completed creation", e)
			}
			saved, e := os.ReadFile(intent)
			if stage != "complete_tmp" && (e != nil || !bytes.Equal(saved, frame)) {
				t.Fatal("read-only changed intent", e)
			}
			s, e = OpenOptionalStore(root, site, key)
			if e != nil {
				t.Fatal(e)
			}
			if len(s.journals) != 1 {
				t.Fatal("missing recovered day")
			}
			for _, j := range s.journals {
				if len(j.entries) != 1 || j.entries[0].Event.RecordID != r.ID {
					t.Fatal("recovery changed record")
				}
			}
			s.Close()
			if e = InspectOptionalStore(root, site, key); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(intent); !os.IsNotExist(e) {
				t.Fatal("intent remained", e)
			}
		})
	}
}

func TestOptionalCreationRejectsMismatchAndOnlyDiscardsUninstalledTmp(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	site := domain.NewID()
	for _, name := range []string{".create-20261005.frame.tmp", ".create-20261005.frame", ".create-20269999.frame.tmp"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			os.Chmod(root, 0700)
			path := filepath.Join(root, name)
			raw := []byte("partial frame")
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if e := InspectOptionalStore(root, site, key); e == nil {
				t.Fatal("pending candidate admitted")
			}
			saved, _ := os.ReadFile(path)
			if !bytes.Equal(saved, raw) {
				t.Fatal("read-only changed candidate")
			}
			s, e := OpenOptionalStore(root, site, key)
			if name == ".create-20261005.frame.tmp" {
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close()
				if s.startupDiscarded != 1 {
					t.Fatal("loss not counted")
				}
				if _, e = os.Stat(path); !os.IsNotExist(e) {
					t.Fatal("candidate remained", e)
				}
			} else {
				if e == nil {
					s.Close()
					t.Fatal("invalid canonical/date repaired")
				}
				saved, _ = os.ReadFile(path)
				if !bytes.Equal(saved, raw) {
					t.Fatal("invalid candidate changed")
				}
			}
		})
	}
}
