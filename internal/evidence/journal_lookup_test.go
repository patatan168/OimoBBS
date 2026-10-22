// 元ID取得の独立所有・追記/部分回収後の現在行と元seq・再起動・停止列拒否を実fileで検査する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestJournalLookupAppendAndOwnedPayload(t *testing.T) {
	j, key, owner, _ := optionalJournalFixture(t)
	defer j.Close()
	first := appendOptionalFixture(t, j, 100, "LOOKUP_ORIGINAL")
	entry, found, e := j.lookupEntry(first.RecordID)
	if e != nil || !found {
		t.Fatal(found, e)
	}
	original := bytes.Clone(entry.Payload)
	entry.Payload[0] ^= 1
	entry.Event.Signature = "changed returned signature"
	again, found, e := j.lookupEntry(first.RecordID)
	if e != nil || !found || !bytes.Equal(again.Payload, original) || again.Event.EventSHA != first.EventSHA {
		t.Fatal("returned lookup changed journal", found, e)
	}
	if _, e := Verify(Source{owner, 20261005, 1}, again.Event, first.PreviousSHA, 10, key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal(e)
	}
	second := appendOptionalFixture(t, j, 200, "LOOKUP_APPENDED")
	added, found, e := j.lookupEntry(second.RecordID)
	if e != nil || !found || added.Event.EventSHA != second.EventSHA {
		t.Fatal("append invisible through existing lookup", found, e)
	}
	if _, e := Verify(Source{owner, 20261005, 2}, added.Event, first.EventSHA, 10, key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal(e)
	}
}

func TestJournalLookupPruneKeepsOriginalSequenceAndRestart(t *testing.T) {
	j, key, owner, path := optionalJournalFixture(t)
	first := appendOptionalFixture(t, j, 100, "LOOKUP_REMOVE")
	second := appendOptionalFixture(t, j, domain.Time(time.Hour)+100, "LOOKUP_RETAIN")
	retained, found, e := j.lookupEntry(second.RecordID)
	if e != nil || !found {
		t.Fatal(found, e)
	}
	if _, found, e := j.lookupEntry(first.RecordID); e != nil || !found {
		t.Fatal(found, e)
	}
	if n, e := j.PruneOptional(100+domain.Time(OptionalRetention), nil); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if _, found, e := j.lookupEntry(first.RecordID); e != nil || found {
		t.Fatal("expired body returned through stale lookup", found, e)
	}
	current, found, e := j.lookupEntry(second.RecordID)
	if e != nil || !found || !bytes.Equal(current.Payload, retained.Payload) || current.Event.EventSHA != second.EventSHA {
		t.Fatal("retained original changed after prune", found, e)
	}
	if _, e := Verify(Source{owner, 20261005, 2}, current.Event, first.EventSHA, 10, key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal("offset reused as source sequence", e)
	}
	if e := j.Close(); e != nil {
		t.Fatal(e)
	}
	if _, _, e := j.lookupEntry(second.RecordID); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("stopped journal lookup allowed", e)
	}
	j, e = OpenJournal(path, owner, 20261005, 10, key, ValidateOptionalPayload)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if _, found, e := j.lookupEntry(first.RecordID); e != nil || found {
		t.Fatal("restart revived expired body", found, e)
	}
	restarted, found, e := j.lookupEntry(second.RecordID)
	if e != nil || !found || restarted.Event.EventSHA != second.EventSHA {
		t.Fatal(found, e)
	}
	third := appendOptionalFixture(t, j, domain.Time(2*time.Hour)+100, "LOOKUP_AFTER_RESTART")
	added, found, e := j.lookupEntry(third.RecordID)
	if e != nil || !found {
		t.Fatal(found, e)
	}
	if _, e := Verify(Source{owner, 20261005, 4}, added.Event, added.Event.PreviousSHA, 10, key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal("post-prune sequence changed", e)
	}
}
