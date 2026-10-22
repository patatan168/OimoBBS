// 案件参照の拒否が全日回収の復旧より先行し、原本/候補を保持することを実fileで検査する。
package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestOptionalStoreCheckedBeforeCheckpointRecovery(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "canonical", true: "candidate"}[pending], func(t *testing.T) {
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
			now := time.Now()
			r := optionalFixture()
			r.Site = site
			r.Received = domain.Time(now.Add(-OptionalRetention + time.Minute).UnixNano())
			r.Finished, r.Until = r.Received+100, r.Received+domain.Time(OptionalRetention)
			if e = s.Write(context.Background(), r); e != nil {
				t.Fatal(e)
			}
			s.checkpoint = func(at string) error {
				if at == "optional:checkpoint_saved" {
					return store.ErrIncomplete
				}
				return nil
			}
			if _, e = s.Sweep(now.Add(2 * time.Minute)); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal(e)
			}
			s.Close()
			day := time.Unix(0, int64(r.Received)).UTC().Format("20060102")
			checkpoint := filepath.Join(root, day+".checkpoint.json")
			if pending {
				if e = os.Rename(checkpoint, checkpoint+".tmp"); e != nil {
					t.Fatal(e)
				}
				checkpoint += ".tmp"
			}
			before := optionalFileTree(t, root)
			rejected := errors.New("signed case reference rejected")
			calls := 0
			guard := func(v OptionalHoldReferences) error {
				calls++
				if rows, e := v.OptionalHoldReceipts(); e != nil || len(rows) != 0 {
					t.Fatal(rows, e)
				}
				return rejected
			}
			if _, e = OpenOptionalStoreChecked(root, site, key, guard); !errors.Is(e, rejected) {
				t.Fatal("open skipped guard", e)
			}
			if e = InspectOptionalStoreChecked(root, site, key, guard); !errors.Is(e, rejected) {
				t.Fatal("inspect skipped guard", e)
			}
			if calls != 2 {
				t.Fatal("guard count", calls)
			}
			after := optionalFileTree(t, root)
			if len(after) != len(before) {
				t.Fatal("rejected guard changed file set")
			}
			for name, raw := range before {
				if !bytes.Equal(raw, after[name]) {
					t.Fatal("rejected guard changed", name)
				}
			}
			s, e = OpenOptionalStoreChecked(root, site, key, func(OptionalHoldReferences) error { return nil })
			if e != nil {
				t.Fatal("allowed recovery failed", e)
			}
			defer s.Close()
			if _, e = os.Stat(filepath.Join(root, day)); !os.IsNotExist(e) {
				t.Fatal("allowed recovery kept day", e)
			}
			if pending {
				if _, e = os.Stat(checkpoint); !os.IsNotExist(e) {
					t.Fatal("allowed recovery kept candidate", e)
				}
			}
		})
	}
}

// optionalFileTree は隔離試験領域のfile内容を再帰取得し、拒否前後の非変更を比較する。
func optionalFileTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	e := filepath.WalkDir(root, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e == nil {
			files[path] = raw
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return files
}
