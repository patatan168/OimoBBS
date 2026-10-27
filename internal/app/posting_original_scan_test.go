// 固定候補の通常/部分回収照合と、10万操作でも一回64行までの進捗を検査する。
package app

import (
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"reflect"
	"testing"
	"time"
)

func TestRequiredOriginalScanSelectsOriginalPairWithoutPayload(t *testing.T) {
	f, p, _, _ := originalReclamationFixture(t)
	scan, e := p.ScanRequiredOriginals([]*evidence.Journal{f.journal}, 0, 64, f.until)
	if e != nil || !scan.Done || scan.Next != 1 || len(scan.Candidates) != 1 || scan.Candidates[0] != f.identity {
		t.Fatal(scan, e)
	}
	next, e := p.ScanRequiredOriginals([]*evidence.Journal{f.journal}, scan.Next, 64, f.until)
	if e != nil || !next.Done || len(next.Candidates) != 0 || next.Next != scan.Next {
		t.Fatal("cursor repeated completed record", next, e)
	}
}

func TestRequiredOriginalScanKeepsPartialAndSkipsFullyRetiredPairs(t *testing.T) {
	for _, side := range []string{"proposal", "decision", "both"} {
		t.Run(side, func(t *testing.T) {
			f, parent, proof, carry := retiredRecoveryFixture(t, side)
			journals := []*evidence.Journal{f.journal}
			p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, journals, f.journal, f.until, proof, &carry, f.key.Public().(ed25519.PublicKey))
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			scan, e := p.ScanRequiredOriginals(journals, 0, 64, f.until)
			if e != nil || !scan.Done || scan.Next != 1 {
				t.Fatal(scan, e)
			}
			want := []evidence.RequiredPostingIdentity{f.identity}
			if side == "both" {
				want = []evidence.RequiredPostingIdentity{}
			}
			if !reflect.DeepEqual(scan.Candidates, want) {
				t.Fatal("retired selection mismatch", scan)
			}
		})
	}
}

func TestRequiredOriginalScanAdvancesBoundedUnexpiredWindow(t *testing.T) {
	// これは本文なし走査窓の検査であり、10万件の製品復旧/回収負荷証明ではない。
	now := domain.Time(time.Now().UnixNano())
	records := make([]store.ThreadRecord, 100000)
	for index := range records {
		records[index] = store.ThreadRecord{Seq: domain.U64(index + 1), Type: "append", Committed: now}
	}
	p := &PostingLog{reclaimed: &reclaimedBody{records: records}}
	for _, after := range []domain.U64{0, 64, 99900} {
		scan, e := p.ScanRequiredOriginals(nil, after, 64, now)
		checkRequiredOriginalScanWindow(t, scan, e, after+64, false)
	}
	scan, e := p.ScanRequiredOriginals(nil, 99990, 64, now)
	checkRequiredOriginalScanWindow(t, scan, e, 100000, true)
}

func checkRequiredOriginalScanWindow(t *testing.T, scan RequiredOriginalScan, e error, next domain.U64, done bool) {
	t.Helper()
	if e != nil || scan.Done != done || scan.Next != next || len(scan.Candidates) != 0 {
		t.Fatal(scan, e)
	}
}
