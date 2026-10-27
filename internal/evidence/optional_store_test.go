// 独立した日別保存の署名・固定期限・全日回収と再起動検査を実fileで確認する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestOptionalStoreRetirementAndClockBoundary(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	site := domain.NewID()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
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
	day, _ := strconv.ParseUint(time.Unix(0, int64(r.Received)).UTC().Format("20060102"), 10, 64)
	dir := filepath.Join(root, strconv.FormatUint(day, 10))
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if len(s.journals[day].entries) != 1 {
		t.Fatal("record not durable")
	}
	if _, e = s.Sweep(now.Add(2 * time.Minute)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("expired original day remained", e)
	}
	checkpoint := filepath.Join(root, strconv.FormatUint(day, 10)+".checkpoint.json")
	raw, e := os.ReadFile(checkpoint)
	if e != nil {
		t.Fatal(e)
	}
	var event Event
	if json.Unmarshal(raw, &event) != nil || event.Kind != "checkpoint" {
		t.Fatal("terminal proof missing")
	}
	checkClock := func(OptionalHoldReferences) error { return nil }
	if e = InspectOptionalStoreCheckedClock(root, site, key, checkClock, domain.Time(now.UnixNano())); !errors.Is(e, ErrRetirementClock) {
		t.Fatal("retirement inspector accepted clock before checkpoint", e)
	}
	if e = InspectOptionalStoreCheckedClock(root, site, key, checkClock, domain.Time(now.Add(3*time.Minute).UnixNano())); e != nil {
		t.Fatal("retirement inspector rejected current clock", e)
	}
	if e = s.Write(context.Background(), optionalFixture()); e == nil {
		t.Fatal("foreign site admitted")
	}
	r.Received = domain.Time(now.UnixNano())
	r.Finished = r.Received + 100
	r.Until = r.Received + domain.Time(OptionalRetention)
	r.ID = domain.NewID()
	if e = s.Write(context.Background(), r); e == nil {
		t.Fatal("clock before durable cleanup admitted")
	}
	s.Close()
	s, e = OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Sweep(now); e == nil || !s.CleanupFailed() {
		t.Fatal("restart lost clock boundary", e)
	}
	if _, e = s.Sweep(now.Add(31 * 24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(checkpoint); !os.IsNotExist(e) {
		t.Fatal("terminal proof expiry extended", e)
	}
	s.Close()
}

func TestOptionalPrunePartialIntentAndMismatch(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		j, key, owner, path := optionalJournalFixture(t)
		appendOptionalFixture(t, j, 100, "EXPIRED_UA")
		_, _ = j.PruneOptional(100+domain.Time(OptionalRetention), func(at string) error {
			if at == "optional:snapshot_intent" {
				return store.ErrIncomplete
			}
			return nil
		})
		j.Close()
		intent := filepath.Join(path, ".optional-prune.snapshot")
		raw, e := os.ReadFile(intent)
		if e != nil {
			t.Fatal(e)
		}
		prefix := raw[:40]
		if corrupt {
			prefix[10] ^= 1
		}
		if e = os.WriteFile(intent, prefix, 0600); e != nil {
			t.Fatal(e)
		}
		j, e = OpenJournal(path, owner, 20261005, 10, key, ValidateOptionalPayload)
		if corrupt {
			if e == nil {
				j.Close()
				t.Fatal("mismatching intent was overwritten")
			}
			saved, _ := os.ReadFile(intent)
			if string(saved) != string(prefix) {
				t.Fatal("mismatching prefix changed")
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		j.Close()
		if _, e = os.Stat(filepath.Join(path, "control-000001.wal")); !os.IsNotExist(e) {
			t.Fatal("expired old bytes remained", e)
		}
	}
}

func TestOptionalStoreRejectsUnknownArtifacts(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, directory := range []bool{false, true} {
		root := t.TempDir()
		if e := os.Chmod(root, 0700); e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(root, "unknown.json")
		if directory {
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
		} else {
			if e := os.WriteFile(path, []byte("private unknown"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		s, e := OpenOptionalStore(root, domain.NewID(), key)
		if e == nil {
			s.Close()
			t.Fatal("unknown artifact accepted")
		}
		if _, e = os.Stat(path); e != nil {
			t.Fatal("unknown artifact changed", e)
		}
	}
}
