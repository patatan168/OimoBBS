// 解除参照の署名保存・旧bytes互換/reader拒否・非復活・改変拒否を実案件fileで検査する。
package disclosure

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestHTTPReleaseReferenceLegacyUnboundAndReaderGate(t *testing.T) {
	s, owner, c, actor, _, _, _, key := reservedHTTPFixtureWithReference(t, false)
	c, e := s.Release(c.ID, actor, c.ETag(), "legacy-release", "cancel", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = owner.ReleaseOptionalHold(context.Background(), c.ID, c.Revision, time.Now()); e != nil {
		t.Fatal(e)
	}
	released, _, e := owner.OptionalHoldReceipt(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	legacy, e := json.Marshal(c.HTTP)
	if e != nil {
		t.Fatal(e)
	}
	var decoded HTTPHold
	if e = json.Unmarshal(legacy, &decoded); e != nil {
		t.Fatal(e)
	}
	back, _ := json.Marshal(decoded)
	if string(back) != string(legacy) {
		t.Fatal("reader42 bytes changed")
	}
	c, e = s.RecordHTTPRelease(c.ID, actor, c.ETag(), released, time.Now())
	if e != nil || c.HTTP.Reservation != nil || c.HTTP.Released == nil {
		t.Fatal(c, e)
	}
	if e = owner.CheckOptionalHoldRelease(*c.HTTP.Released); e != nil {
		t.Fatal(e)
	}
	again, e := s.RecordHTTPRelease(c.ID, actor, c.ETag(), released, time.Now())
	if e != nil || again.ETag() != c.ETag() {
		t.Fatal("release replay added audit", again, e)
	}
	root := s.root
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if e = InspectVersion(root, key, 42); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("reader42 accepted new release reference", e)
	}
	if e = InspectVersion(root, key, 43); e != nil {
		t.Fatal("reader43 rejected release reference", e)
	}
	s, e = Open(root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.Get(c.ID)
	if e != nil || got.HTTP.Released.SHA != released.SHA || got.State != "closed" {
		t.Fatal(got, e)
	}
	bad := released
	bad.SHA = domain.Hash{1}
	if _, e = s.RecordHTTPRelease(c.ID, actor, got.ETag(), bad, time.Now()); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("saved release replaced", e)
	}
	if _, e = s.HTTPRecords(got, time.Now()); !errors.Is(e, ErrExpired) {
		t.Fatal("release metadata revived disclosure", e)
	}
}
