// 多数の部分満了を単一snapshotへまとめ、署名連鎖と停止後の再開を検査する。
package evidence

import (
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOptionalBulkPruneSingleSnapshotAndStop(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprint(stop), func(t *testing.T) {
			j, key, owner, path := optionalJournalFixture(t)
			expired := make([]domain.ID, 0, 1025)
			for i := 0; i < 1025; i++ {
				e := appendOptionalFixture(t, j, 100, fmt.Sprintf("EXPIRED-%04d-", i)+strings.Repeat("x", 6000))
				expired = append(expired, e.RecordID)
			}
			live := appendOptionalFixture(t, j, 1000, "LIVE_USER_AGENT")
			checkpoints := 0
			started := time.Now()
			n, e := j.PruneOptionalAll(200+domain.Time(OptionalRetention), func(stage string) error {
				if stage == "optional:removed" {
					checkpoints++
					if stop && checkpoints == 2 {
						return store.ErrIncomplete
					}
				}
				return nil
			})
			if stop {
				if e == nil || n != 256 {
					t.Fatal("stop not observed", n, e)
				}
				j.Close()
				j, e = OpenJournal(path, owner, 20261005, 10, key, ValidateOptionalPayload)
				if e != nil {
					t.Fatal(e)
				}
				if n, e = j.PruneOptionalAll(200+domain.Time(OptionalRetention), nil); e != nil || n != 769 {
					t.Fatal(n, e)
				}
			} else if e != nil || n != 1025 {
				t.Fatal(n, e)
			}
			elapsed := time.Since(started)
			t.Logf("1025 expired / 1 retained, stop=%v, reclaim=%s", stop, elapsed)
			if elapsed >= 5*time.Minute {
				t.Fatal("missed five-minute bound", elapsed)
			}
			if !stop {
				manifest, e := store.InspectControlManifest(path)
				if e != nil {
					t.Fatal(e)
				}
				if manifest.Generation != 2 {
					t.Fatal("more than one snapshot switch", manifest.Generation)
				}
			}
			if _, e = os.Stat(filepath.Join(path, "control-000001.wal")); !os.IsNotExist(e) {
				t.Fatal("old bytes remained", e)
			}
			j.Close()
			j, e = OpenJournal(path, owner, 20261005, 10, key, ValidateOptionalPayload)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			if j.seq != 1035 || len(j.entries) != 10 {
				t.Fatal("source chain", j.seq, len(j.entries))
			}
			for _, id := range expired {
				if !j.ids[id] {
					t.Fatal("retired ID reused", id)
				}
			}
			found := false
			for _, entry := range j.Entries() {
				if entry.Event.RecordID == live.RecordID {
					found = true
					if entry.Event != live {
						t.Fatal("retained signature changed")
					}
				}
			}
			if !found {
				t.Fatal("retained row missing")
			}
		})
	}
}
