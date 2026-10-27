// 実投稿停止から未受理確定・24時間/7日回収・公開保持・再起動を通して検査する。
package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func rejectedPostingFixture(t *testing.T, reply bool) (*PostingLog, *evidence.Journal, []byte, domain.Time, ed25519.PrivateKey) {
	t.Helper()
	p, j, create, now, _, signing := newPostingTest(t)
	rejected := create
	if reply {
		if result := p.Post(t.Context(), create, []byte(`{"fixture":true}`), now); result.Status != store.Durable {
			t.Fatal(result)
		}
		rejected = replyFixture(t, create)
	}
	p.checkpoint = func(stage string) error {
		if stage == "proposal" {
			return errors.New("stop before public WAL")
		}
		return nil
	}
	if result := p.Post(t.Context(), rejected, []byte(`{"fixture":false}`), now); result.Status != store.Unknown {
		t.Fatal(result)
	}
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
	restored, e := OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = restored.Close() })
	return restored, j, rejected, now, signing
}

func TestRejectedOriginalsTwoDeadlinesAndLiveRestart(t *testing.T) {
	p, j, rejected, now, _ := rejectedPostingFixture(t, true)
	journals := []*evidence.Journal{j}
	at := now + domain.Time(24*time.Hour)
	candidates, e := p.RejectedOriginalCandidates(journals, at-1, noOriginalPairHold)
	if e != nil || len(candidates) != 0 {
		t.Fatal(candidates, e)
	}
	candidates, e = p.RejectedOriginalCandidates(journals, at, noOriginalPairHold)
	if e != nil || len(candidates) != 1 {
		t.Fatal(candidates, e)
	}
	if n, e := p.PruneRequiredOriginalBatch(t.Context(), journals, j, candidates, at, nil, noOriginalPairHold); n != 2 || e != nil {
		t.Fatal(n, e)
	}
	assertRejectedOriginalAbsent(t, p, j, rejected, candidates[0])
	if !RejectedConnectionPending(j) || p.HasUnretiredRejections() {
		t.Fatal("two-stage retention not reflected")
	}
	p = reopenRejectedLive(t, p, j, at, rejected)
	defer p.Close()
	checkRejectedConnectionExpiry(t, p, j, now)

}

func assertRejectedOriginalAbsent(t *testing.T, p *PostingLog, j *evidence.Journal, rejected []byte, i evidence.RequiredPostingIdentity) {
	t.Helper()
	entry := p.proposals[i.OperationID]
	if entry.payload.Frame != "" || len(entry.payload.Capture) != 0 || entry.event.Payload != "" {
		t.Fatal("rejected body/capture retained in memory")
	}
	files := retirementFiles(t, filepath.Join(filepath.Dir(p.parent), "20231114"))
	for name, raw := range files {
		if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(rejected))) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"fixture":false}`)))) {
			t.Fatal("rejected original retained", name)
		}
	}
	assertRejectedRetirementDeadlines(t, j, i)
}

func TestRejectedOriginalsHeldAndFailedProtectionKeepFiles(t *testing.T) {
	p, j, _, now, _ := rejectedPostingFixture(t, false)
	at := now + domain.Time(24*time.Hour)
	candidates, e := p.RejectedOriginalCandidates([]*evidence.Journal{j}, at, noOriginalPairHold)
	if e != nil || len(candidates) != 1 {
		t.Fatal(candidates, e)
	}
	path := filepath.Join(filepath.Dir(p.parent), "20231114")
	before := retirementFiles(t, path)
	held := func(evidence.RequiredPostingIdentity, domain.Time) (bool, error) { return true, nil }
	if n, e := p.PruneRequiredOriginalBatch(t.Context(), []*evidence.Journal{j}, j, candidates, at, nil, held); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	failure := errors.New("source protection unavailable")
	broken := func(evidence.RequiredPostingIdentity, domain.Time) (bool, error) { return false, failure }
	if n, e := p.PruneRequiredOriginalBatch(t.Context(), []*evidence.Journal{j}, j, candidates, at, nil, broken); n != 0 || !errors.Is(e, failure) {
		t.Fatal(n, e)
	}
	if !reflect.DeepEqual(before, retirementFiles(t, path)) || p.stopped {
		t.Fatal("protected/preflight failure changed or stopped owner")
	}
	if _, e = os.Stat(filepath.Join(p.parent, "1700000000")); !os.IsNotExist(e) {
		t.Fatal("rejected create acquired public storage", e)
	}
}

func TestRejectedOriginalsInterruptedTwoStageRecovery(t *testing.T) {
	for _, stage := range []string{"connection_saved", "required:removed", "required:snapshot_intent", "required:snapshot_current"} {
		t.Run(stage, func(t *testing.T) { checkRejectedInterruptedStage(t, stage) })
	}
}

func checkRejectedInterruptedStage(t *testing.T, stage string) {
	t.Helper()
	p, j, rejected, now, signing := rejectedPostingFixture(t, true)
	at := now + domain.Time(24*time.Hour)
	journals := []*evidence.Journal{j}
	candidates, e := p.RejectedOriginalCandidates(journals, at, noOriginalPairHold)
	if e != nil || len(candidates) != 1 {
		t.Fatal(candidates, e)
	}
	if e = p.preserveRejectedConnections(journals, candidates, at); e != nil {
		t.Fatal(e)
	}
	if stage != "connection_saved" {
		interruptRejectedPrune(t, j, candidates[0], at, stage)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(p.parent), "20231114")
	before := retirementFiles(t, path)
	inspection, e := evidence.InspectJournal(path, p.owner, 20231114, 10, signing, PostingValidator(fixtureCapture))
	if e != nil || inspection.MinimumReader != 52 || !reflect.DeepEqual(before, retirementFiles(t, path)) {
		t.Fatal("read-only recovery boundary", inspection, e)
	}
	recoverRejectedInterruptedFixture(t, p, path, signing, rejected, at)
}

func interruptRejectedPrune(t *testing.T, j *evidence.Journal, i evidence.RequiredPostingIdentity, at domain.Time, stage string) {
	t.Helper()
	stop := errors.New("simulated interruption")
	selectIdentity := func(entry evidence.Entry) (*evidence.RequiredPostingIdentity, error) {
		if entry.Event.RecordID == i.ProposalID || entry.Event.RecordID == i.DecisionID {
			return &i, nil
		}
		return nil, nil
	}
	n, e := j.PruneRequired(at, selectIdentity, noRetirementHold, func(checkpoint string) error {
		if checkpoint == stage {
			return stop
		}
		return nil
	})
	if n != 2 || !errors.Is(e, stop) {
		t.Fatal(n, e)
	}
}

func recoverRejectedInterruptedFixture(t *testing.T, old *PostingLog, path string, signing ed25519.PrivateKey, rejected []byte, at domain.Time) {
	t.Helper()
	j, e := evidence.OpenJournal(path, old.owner, 20231114, 10, signing, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	p, e := OpenPosting(old.parent, old.owner, old.key, []*evidence.Journal{j}, j, at)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	candidates, e := p.RejectedOriginalCandidates([]*evidence.Journal{j}, at, noOriginalPairHold)
	if e != nil {
		t.Fatal(e)
	}
	if len(candidates) != 0 {
		if _, e = p.PruneRequiredOriginalBatch(t.Context(), []*evidence.Journal{j}, j, candidates, at, nil, noOriginalPairHold); e != nil {
			t.Fatal(e)
		}
	}
	if p.Snapshot(at).PostCount != 1 {
		t.Fatal("interruption lost public post")
	}
	for name, raw := range retirementFiles(t, path) {
		if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(rejected))) {
			t.Fatal("old original survived restart", name)
		}
	}
}

func reopenRejectedLive(t *testing.T, p *PostingLog, j *evidence.Journal, at domain.Time, rejected []byte) *PostingLog {
	t.Helper()
	journals := []*evidence.Journal{j}
	if p.Snapshot(at).PostCount != 1 {
		t.Fatal("accepted public post lost")
	}
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
	opened, e := OpenPostingsWithRetiredOriginals(p.parent, p.owner, []uint64{p.key}, journals, j, at, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	p = opened[p.key]
	if result := p.Post(t.Context(), rejected, []byte(`{"fixture":false}`), at); result.Status != store.NotWritten {
		t.Fatal("rejected operation reused", result)
	}
	if _, e = OpenPostingsWithRetiredOriginals(p.parent, p.owner, nil, journals, j, at-1, nil, nil, nil); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal(e)
	}

	return p
}

func checkRejectedConnectionExpiry(t *testing.T, p *PostingLog, j *evidence.Journal, now domain.Time) {
	t.Helper()
	seven := now + domain.Time(7*24*time.Hour)
	payload := rejectedConnectionPayload(t, j)
	assertRejectedDecisionMetadata(t, j, now)
	if n, e := PruneRejectedConnections(t.Context(), j, seven-1, noOriginalPairHold); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := PruneRejectedConnections(t.Context(), j, seven, noOriginalPairHold); n != 1 || e != nil {
		t.Fatal(n, e)
	}
	assertRejectedConnectionPhysicalAbsence(t, p, payload)
	if RejectedConnectionPending(j) {
		t.Fatal("expired connection retained")
	}
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
	p, e := OpenPosting(p.parent, p.owner, p.key, []*evidence.Journal{j}, j, seven)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if p.Snapshot(seven).PostCount != 1 {
		t.Fatal("accepted post lost after connection cleanup")
	}
}

func assertRejectedRetirementDeadlines(t *testing.T, j *evidence.Journal, i evidence.RequiredPostingIdentity) {
	t.Helper()
	retired, e := j.RequiredRetirements()
	if e != nil || len(retired) != 2 {
		t.Fatal(retired, e)
	}
	for _, r := range retired {
		if r.Identity.Outcome != "not_accepted" || r.Until != i.Committed+domain.Time(24*time.Hour) {
			t.Fatal(r)
		}
	}
}

func rejectedConnectionPayload(t *testing.T, j *evidence.Journal) string {
	t.Helper()
	for _, entry := range j.Entries() {
		if entry.Event.Kind == rejectedConnectionKind {
			return entry.Event.Payload
		}
	}
	t.Fatal("missing 7-day connection record")
	return ""
}

func assertRejectedConnectionPhysicalAbsence(t *testing.T, p *PostingLog, payload string) {
	t.Helper()
	for name, raw := range retirementFiles(t, filepath.Join(filepath.Dir(p.parent), "20231114")) {
		if bytes.Contains(raw, []byte(payload)) {
			t.Fatal("expired connection retained in old generation", name)
		}
	}
}

func assertRejectedDecisionMetadata(t *testing.T, j *evidence.Journal, now domain.Time) {
	t.Helper()
	for _, entry := range j.Entries() {
		if entry.Event.Kind != rejectedConnectionKind {
			continue
		}
		var v rejectedConnection
		if e := json.Unmarshal(entry.Payload, &v); e != nil {
			t.Fatal(e)
		}
		if v.Decided != now || !v.Recovered {
			t.Fatal("recovery decision metadata lost")
		}
	}
}
