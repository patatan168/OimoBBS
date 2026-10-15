// 自動回収cursorの遷移・snapshot・時計/reader/scope差替えを非変更で検査する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
)

func requiredGCStateJSON(t *testing.T, v requiredGCState) json.RawMessage {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestRequiredGCStateForwardWindowAndSnapshot(t *testing.T) {
	v := requiredGCState{Schema: requiredGCStateSchema, Site: domain.NewID(), Enabled: true, Round: 1, At: 10}
	if e := validateRequiredGCState("originals", nil, requiredGCStateJSON(t, v)); e != nil {
		t.Fatal(e)
	}
	next := v
	id := domain.NewID()
	next.Board, next.Key, next.At = &id, 1700000000, 11
	checkRequiredGCStateTransition(t, v, next, true)
	v = next
	next.Proof[0], next.Day, next.At = 1, 20251005, 12
	checkRequiredGCStateTransition(t, v, next, true)
	v = next
	next.After, next.Day, next.Advance, next.At = 64, 0, true, 13
	checkRequiredGCStateTransition(t, v, next, true)
	if e := snapshotSiteValue("required_gc", "originals", nil, requiredGCStateJSON(t, next)); e != nil {
		t.Fatal("completed cursor refused snapshot", e)
	}
	v = next
	next.Round++
	next.After, next.Proof, next.Advance, next.At = 0, domain.Hash{}, false, 14
	checkRequiredGCStateTransition(t, v, next, true)
}

func checkRequiredGCStateTransition(t *testing.T, previous, next requiredGCState, allowed bool) {
	t.Helper()
	e := validateRequiredGCState("originals", requiredGCStateJSON(t, previous), requiredGCStateJSON(t, next))
	if (e == nil) != allowed {
		t.Fatal(previous, next, e)
	}
}

func TestRequiredGCStateRejectsRegressionsAndUnapprovedScopeChanges(t *testing.T) {
	id := domain.NewID()
	v := requiredGCState{Schema: requiredGCStateSchema, Site: domain.NewID(), Board: &id, Key: 1, Round: 1, After: 64, Day: 20251005, At: 20}
	v.Proof[0] = 1
	changes := []func(*requiredGCState){
		func(n *requiredGCState) { n.After-- },
		func(n *requiredGCState) { n.Day-- },
		func(n *requiredGCState) { n.At-- },
		func(n *requiredGCState) { n.Proof[0]++ },
		func(n *requiredGCState) { n.Site = domain.NewID() },
		func(n *requiredGCState) { id := domain.NewID(); n.Board = &id },
		func(n *requiredGCState) { n.Key++ },
		func(n *requiredGCState) { n.Round++ },
		func(n *requiredGCState) { n.After++; n.Day = 20251006 },
	}
	for _, change := range changes {
		next := v
		change(&next)
		checkRequiredGCStateTransition(t, v, next, false)
	}
}

// TestRequiredGCStateReaderAndClockGate は設定だけが新しい保存先を復旧前に拒否する。
func TestRequiredGCStateReaderAndClockGate(t *testing.T) {
	site := siteState{ID: domain.NewID(), MinimumReader: 48}
	v := requiredGCState{Schema: requiredGCStateSchema, Site: site.ID, Enabled: true, Round: 1, At: 20}
	state := store.ControlState{Rows: map[string]store.ControlRow{"required_gc:originals": {Value: requiredGCStateJSON(t, v)}}}
	if job, e := readRequiredGCState(state, site, 20); e != nil || job == nil {
		t.Fatal(job, e)
	}
	site.MinimumReader = 47
	if _, e := readRequiredGCState(state, site, 20); e == nil {
		t.Fatal("reader47 accepted new GC state")
	}
	site.MinimumReader = 48
	if _, e := readRequiredGCState(state, site, 19); e == nil {
		t.Fatal("clock rollback accepted GC state")
	}
	site.ID = domain.NewID()
	if _, e := readRequiredGCState(state, site, 20); e == nil {
		t.Fatal("foreign site accepted GC state")
	}
}
