// 未受理の照会が受理投稿や入力本文を混ぜず、24時間移行後も固定対象を維持することを検査する。
package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
	"time"
)

func TestRejectedRecordsProjectionAndRetention(t *testing.T) {
	p, j, _, now, _ := rejectedPostingFixture(t, true)
	journals := []*evidence.Journal{j}
	all := func(domain.ID, domain.U64, domain.Time, domain.ID) bool { return true }
	rows, e := RejectedRecordsInRange(journals, all, 100, now)
	if e != nil || len(rows) != 1 {
		t.Fatal(len(rows), e)
	}
	original := rows[0]
	originalSnapshot, e := EncodeRejectedSnapshot(original)
	if e != nil {
		t.Fatal(e)
	}
	projected, e := original.Project([]string{"connection"})
	raw, _ := json.Marshal(projected)
	if e != nil || projected["public_state"] != "not_accepted" || projected["connection_missing_reason"] != "not_collected" {
		t.Fatal(projected, e)
	}
	for _, secret := range []string{"capture", "prepared_frame", "fixture", "principal", "input"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private input in projection", secret)
		}
	}
	if _, e = original.Project([]string{"content"}); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("content selected", e)
	}
	forged := original
	forged.SourceSHA[0] ^= 1
	if _, e = forged.Project(nil); e == nil {
		t.Fatal("edited source accepted")
	}
	match := func(board domain.ID, key domain.U64, at domain.Time, id domain.ID) bool {
		return board == original.Board && key == original.Thread && at == original.Committed && id == original.RecordID
	}
	rows, e = RejectedRecordsInRange(journals, match, 1, now)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	none := func(domain.ID, domain.U64, domain.Time, domain.ID) bool { return false }
	rows, e = RejectedRecordsInRange(journals, none, 1, now)
	if e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
	at := now + domain.Time(24*time.Hour)
	candidates, e := p.RejectedOriginalCandidates(journals, at, noOriginalPairHold)
	if e != nil || len(candidates) != 1 {
		t.Fatal(candidates, e)
	}
	if n, e := p.PruneRequiredOriginalBatch(t.Context(), journals, j, candidates, at, nil, noOriginalPairHold); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	rows, e = RejectedRecordsInRange(journals, match, 1, at)
	if e != nil || len(rows) != 1 || rows[0].Source() != original.Source() || rows[0].SourceID == original.SourceID {
		t.Fatal(rows, e)
	}
	snapshot, e := EncodeRejectedSnapshot(rows[0])
	if e != nil || !bytes.Equal(snapshot, originalSnapshot) {
		t.Fatal("copy changed after original migration", e)
	}
	if _, e = RejectedRecordsInRange(journals, match, 1, at-1); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("clock rollback accepted", e)
	}
	if n, e := PruneRejectedConnections(t.Context(), j, original.Expires, func(evidence.RequiredPostingIdentity, domain.Time) (bool, error) { return true, nil }); e != nil || n != 0 {
		t.Fatal("reserved source pruned", n, e)
	}
	reserved, e := RejectedReservedRecords(journals, []RejectedSource{original.Source()}, now, original.Expires+domain.Time(24*time.Hour), original.Expires)
	if e != nil || len(reserved) != 1 {
		t.Fatal("reserved expired source missing", reserved, e)
	}
	rows, e = RejectedRecordsInRange(journals, all, 100, original.Expires)
	if e != nil || len(rows) != 0 {
		t.Fatal("7d expiry", rows, e)
	}
}

func TestRejectedProjectionOwnsConnection(t *testing.T) {
	p, j, _, now, _ := rejectedPostingFixture(t, false)
	rows, e := RejectedRecordsInRange([]*evidence.Journal{j}, func(domain.ID, domain.U64, domain.Time, domain.ID) bool { return true }, 1, now)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	row := rows[0]
	observation := rejectedObservedRequest(t, p.owner)
	row.value.Observation = &observation
	row.value.Missing = ""
	first, e := row.Project([]string{"connection"})
	if e != nil {
		t.Fatal(e)
	}
	first["connection"].(*evidence.HTTPObservation).Peer.IP = "edited"
	second, e := row.Project([]string{"connection"})
	if e != nil || second["connection"].(*evidence.HTTPObservation).Peer.IP != observation.Peer.IP {
		t.Fatal("projection mutated source", e)
	}
}
