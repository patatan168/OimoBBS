// 署名欠測集計の再起動、未確認区間、原子的更新の停止点と改変拒否を実fileで検査する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func optionalLossFixture(t *testing.T) (string, domain.ID, ed25519.PrivateKey, *OptionalLossStore, time.Time) {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	site := domain.NewID()
	s, e := OpenOptionalLoss(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	if _, e = s.Begin(now, 0); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close(); clear(key) })
	return root, site, key, s, now
}

func TestOptionalLossRestartAndUncertainty(t *testing.T) {
	root, site, key, s, now := optionalLossFixture(t)
	status := OptionalStatus{Accepted: 3, Saved: 1, Failed: 1, Pending: 1, PendingBytes: 100, DroppedCapacity: 2, LossStarted: domain.Time(now.Add(time.Second).UnixNano()), LossFinished: domain.Time(now.Add(time.Second).UnixNano())}
	first, e := s.Capture(status, now.Add(2*time.Second), false)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	reopened, e := OpenOptionalLoss(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if _, e := reopened.Capture(OptionalStatus{}, now.Add(3*time.Second), false); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("new boot was not required", e)
	}
	next, e := reopened.Begin(now.Add(3*time.Second), 4)
	if e != nil {
		t.Fatal(e)
	}
	known, e := next.Known()
	if e != nil || known.Failed != 1 || known.Capacity != 2 || known.StartupDiscarded != 4 || known.Shutdown != 0 || next.UncleanBoots != 1 || next.UnknownFrom != first.Observed || next.UnknownUntil != next.Opened || next.KnownLossFrom != first.Queue.LossStarted || next.KnownLossUntil != first.Queue.LossFinished {
		t.Fatal(next, known, e)
	}
	if _, e := reopened.Begin(now.Add(4*time.Second), 0); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("boot begun twice", e)
	}
	// 待機中だった1件を既知の欠測件数へ推測で追加しない。
	final, e := reopened.Capture(OptionalStatus{Closed: true}, now.Add(4*time.Second), true)
	if e != nil || !final.Clean {
		t.Fatal(final, e)
	}
	reopened.Close()
	third, e := OpenOptionalLoss(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer third.Close()
	last, e := third.Begin(now.Add(5*time.Second), 0)
	if e != nil || last.UncleanBoots != 1 || last.Prior != known {
		t.Fatal(last, e)
	}
	raw, e := os.ReadFile(filepath.Join(root, OptionalLossFile))
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"peer", "user_agent", "request_id", "PRIVATE_BODY", "192.0.2.1"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private field in loss summary", secret)
		}
	}
	if e = InspectOptionalLoss(root, site, key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal(e)
	}
}

func TestOptionalLossAtomicRecovery(t *testing.T) {
	for _, stage := range []string{"loss:candidate_synced", "loss:renamed"} {
		t.Run(stage, func(t *testing.T) {
			root, site, key, s, now := optionalLossFixture(t)
			stopped := errors.New("simulated stop")
			s.checkpoint = func(at string) error {
				if at == stage {
					return stopped
				}
				return nil
			}
			status := OptionalStatus{DroppedInvalid: 1, LossStarted: domain.Time(now.Add(time.Second).UnixNano()), LossFinished: domain.Time(now.Add(time.Second).UnixNano())}
			if _, e := s.Capture(status, now.Add(2*time.Second), false); !errors.Is(e, stopped) {
				t.Fatal(e)
			}
			if _, e := s.Capture(status, now.Add(3*time.Second), false); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("stopped owner reused", e)
			}
			before, _ := os.ReadFile(filepath.Join(root, OptionalLossFile))
			inspect := InspectOptionalLoss(root, site, key.Public().(ed25519.PublicKey))
			if stage == "loss:candidate_synced" && !errors.Is(inspect, store.ErrIncomplete) || stage == "loss:renamed" && inspect != nil {
				t.Fatal(inspect)
			}
			after, _ := os.ReadFile(filepath.Join(root, OptionalLossFile))
			if !bytes.Equal(before, after) {
				t.Fatal("inspect mutated current")
			}
			s.Close()
			resumed, e := OpenOptionalLoss(root, site, key)
			if e != nil {
				t.Fatal(e)
			}
			defer resumed.Close()
			summary, ok := resumed.Summary()
			if !ok || summary.Queue.DroppedInvalid != 1 || summary.Sequence != 2 {
				t.Fatal(summary)
			}
			if _, e = os.Stat(filepath.Join(root, optionalLossCandidate)); !os.IsNotExist(e) {
				t.Fatal("candidate retained", e)
			}
		})
	}
}

func TestOptionalLossRejectsTamperAndTransitions(t *testing.T) {
	root, site, key, s, now := optionalLossFixture(t)
	base := OptionalStatus{Accepted: 1, Failed: 1, LossStarted: domain.Time(now.Add(time.Second).UnixNano()), LossFinished: domain.Time(now.Add(time.Second).UnixNano())}
	if _, e := s.Capture(base, now.Add(2*time.Second), false); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Capture(OptionalStatus{}, now.Add(3*time.Second), false); e == nil {
		t.Fatal("loss counters decreased")
	}
	if _, e := s.Capture(base, now.Add(time.Second), false); e == nil {
		t.Fatal("clock rollback accepted")
	}
	if _, e := s.Capture(base, now.Add(3*time.Second), true); e == nil {
		t.Fatal("open queue marked clean")
	}
	raw, e := os.ReadFile(filepath.Join(root, OptionalLossFile))
	if e != nil {
		t.Fatal(e)
	}
	var env optionalLossEnvelope
	json.Unmarshal(raw, &env)
	var v OptionalLossSummary
	json.Unmarshal(env.Summary, &v)
	v.Queue.Failed = 0
	env.Summary, _ = json.Marshal(v)
	changed, _ := json.Marshal(env)
	if e = os.WriteFile(filepath.Join(root, OptionalLossFile), changed, 0600); e != nil {
		t.Fatal(e)
	}
	if e = InspectOptionalLoss(root, site, key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("signed loss summary altered")
	}
	if e = os.WriteFile(filepath.Join(root, OptionalLossFile), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = InspectOptionalLoss(root, domain.NewID(), key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("wrong site accepted")
	}
	if e = os.WriteFile(filepath.Join(root, optionalLossCandidate), []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenOptionalLoss(root, site, key); e == nil {
		t.Fatal("invalid candidate accepted")
	}
	candidate, _ := os.ReadFile(filepath.Join(root, optionalLossCandidate))
	if string(candidate) != "partial" {
		t.Fatal("invalid candidate deleted")
	}
}

func TestOptionalLossInitialCandidateRecovery(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer clear(key)
	site := domain.NewID()
	s, e := OpenOptionalLoss(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	s.checkpoint = func(string) error { return errors.New("first creation stop") }
	if _, e = s.Begin(time.Now(), 0); e == nil {
		t.Fatal("stop ignored")
	}
	s.Close()
	if _, e = os.Stat(filepath.Join(root, OptionalLossFile)); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if e = InspectOptionalLoss(root, site, key.Public().(ed25519.PublicKey)); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal(e)
	}
	resumed, e := OpenOptionalLoss(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer resumed.Close()
	v, ok := resumed.Summary()
	if !ok || v.Sequence != 1 || v.Clean || v.Completeness != "snapshot_only" {
		t.Fatal(v)
	}
}

func TestOptionalLossCountIntegrity(t *testing.T) {
	root, _, _, s, now := optionalLossFixture(t)
	before, e := os.ReadFile(filepath.Join(root, OptionalLossFile))
	if e != nil {
		t.Fatal(e)
	}
	for _, invalid := range []OptionalStatus{{Accepted: 1}, {Accepted: 1, Pending: 1}, {Accepted: ^uint64(0), Saved: ^uint64(0), Failed: 1}} {
		if _, e = s.Capture(invalid, now.Add(time.Second), false); e == nil {
			t.Fatal("inconsistent queue counters accepted", invalid)
		}
	}
	after, e := os.ReadFile(filepath.Join(root, OptionalLossFile))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid counters changed durable summary", e)
	}
}
