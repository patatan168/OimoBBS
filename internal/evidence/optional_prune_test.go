// 非必須ログの満了回収・元署名連鎖・途中停止と旧世代bytes消去を実fileで確認する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func optionalJournalFixture(t *testing.T) (*Journal, ed25519.PrivateKey, domain.ID, string) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	owner := domain.NewID()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "20261005")
	j, e := OpenJournal(path, owner, 20261005, 10, key, ValidateOptionalPayload)
	if e != nil {
		t.Fatal(e)
	}
	return j, key, owner, path
}

func appendOptionalFixture(t *testing.T, j *Journal, received domain.Time, ua string) Event {
	t.Helper()
	r := optionalFixture()
	r.Received = received
	r.Finished = received + 100
	r.Until = received + domain.Time(OptionalRetention)
	if ua != "" {
		h := encodeHeaderValue(ua)
		r.UserAgent = &h
	}
	event, result := j.Append(r.ID, "attempt", r.Finished, func(src Source) ([]byte, error) {
		return json.Marshal(OptionalPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), r})
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	return event
}

func TestOptionalPrunePartialExpiryAndChain(t *testing.T) {
	j, key, owner, path := optionalJournalFixture(t)
	first := appendOptionalFixture(t, j, 100, "UNIQUE_EXPIRED_USER_AGENT")
	second := appendOptionalFixture(t, j, domain.Time(time.Hour)+100, "RETAINED_USER_AGENT")
	n, e := j.PruneOptional(100+domain.Time(OptionalRetention), nil)
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if len(j.Entries()) != 2 {
		t.Fatal("expected retained record and tombstone")
	}
	appendOptionalFixture(t, j, domain.Time(2*time.Hour)+100, "LATER_USER_AGENT")
	if j.seq != 4 || !j.ids[first.RecordID] {
		t.Fatal("source seq or retired ID lost")
	}
	j.Close()
	j, e = OpenJournal(path, owner, 20261005, 10, key, ValidateOptionalPayload)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if j.seq != 4 || !j.ids[first.RecordID] {
		t.Fatal("retired metadata lost")
	}
	found := false
	for _, entry := range j.Entries() {
		if entry.Event.RecordID == second.RecordID {
			found = true
			if entry.Event.EventSHA != second.EventSHA {
				t.Fatal("live signature changed")
			}
		}
	}
	if !found {
		t.Fatal("live row disappeared")
	}
	entries, _ := os.ReadDir(path)
	for _, entry := range entries {
		raw, e := os.ReadFile(filepath.Join(path, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, []byte("UNIQUE_EXPIRED_USER_AGENT")) {
			t.Fatal("expired bytes remained", entry.Name())
		}
	}
	if _, e = os.Stat(filepath.Join(path, "control-000001.wal")); !os.IsNotExist(e) {
		t.Fatal("old original WAL remained", e)
	}
}

func TestOptionalPruneInterruptedRecovery(t *testing.T) {
	for _, stage := range []string{"optional:removed", "optional:snapshot_intent", "optional:snapshot_current"} {
		t.Run(stage, func(t *testing.T) {
			j, key, owner, path := optionalJournalFixture(t)
			appendOptionalFixture(t, j, 100, "PRIVATE_EXPIRED_UA")
			stop := errors.New("interrupted")
			n, e := j.PruneOptional(100+domain.Time(OptionalRetention), func(at string) error {
				if at == stage {
					return stop
				}
				return nil
			})
			if n != 1 || !errors.Is(e, stop) {
				t.Fatal(n, e)
			}
			j.Close()
			j, e = OpenJournal(path, owner, 20261005, 10, key, ValidateOptionalPayload)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			if len(j.Entries()) != 1 || j.Entries()[0].Event.Kind != "tombstone" {
				t.Fatal("expired record restored")
			}
			if _, e = os.Stat(filepath.Join(path, "control-000001.wal")); !os.IsNotExist(e) {
				t.Fatal("expired generation remained", e)
			}
			if _, e = os.Stat(filepath.Join(path, ".optional-prune.snapshot")); !os.IsNotExist(e) {
				t.Fatal("intent remained", e)
			}
		})
	}
}
