// 案件コピー用の元bytes取得・署名束縛・正本非変更・回収後の独立検証を実fileで検査する。
package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

func signedOptionalFixture(t *testing.T) (*OptionalStore, ed25519.PrivateKey, OptionalRecord, OptionalQueryScope) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	r := optionalFixture()
	board, operation := domain.NewID(), domain.NewID()
	r.Board, r.Operation, r.Outcome = &board, &operation, "accepted"
	r.Received = domain.Time(time.Now().Add(-time.Hour).UnixNano())
	r.Finished, r.Until = r.Received+100, r.Received+domain.Time(OptionalRetention)
	s, e := OpenOptionalStore(root, r.Site, key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close(); clear(key) })
	if e = s.Write(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	return s, key, r, OptionalQueryScope{Board: board, From: r.Received, To: r.Received + 1000, Operations: []domain.ID{operation}}
}

func TestOptionalSignedQueryIndependentVerification(t *testing.T) {
	s, key, record, scope := signedOptionalFixture(t)
	rows, e := s.QuerySigned(context.Background(), scope, time.Now())
	if e != nil || len(rows) != 1 {
		t.Fatal(len(rows), e)
	}
	entry := rows[0]
	got, e := VerifyOptionalEntry(entry, record.Site, key.Public().(ed25519.PublicKey))
	if e != nil || got.Record.ID != record.ID || got.SourceSHA != entry.Event.EventSHA || got.SourceSeq != 1 {
		t.Fatal(got, e)
	}
	// 署名付き結果の変更は、正本payloadと署名envelopeへ影響しない。
	rows[0].Payload[0] = '!'
	rows[0].Event.Signature = "changed"
	again, e := s.QuerySigned(context.Background(), scope, time.Now())
	if e != nil || len(again) != 1 {
		t.Fatal(e)
	}
	if _, e = VerifyOptionalEntry(again[0], record.Site, key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal("source alias", e)
	}
	entry = again[0]
	if _, e = s.Sweep(time.Unix(0, int64(record.Until))); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyOptionalEntry(entry, record.Site, key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal("copy required removed source", e)
	}
	expired, e := s.QuerySigned(context.Background(), scope, time.Unix(0, int64(record.Until)))
	if e != nil || len(expired) != 0 {
		t.Fatal("expired source returned", expired, e)
	}
}

func TestOptionalEntryRejectsTamperAndCrossSource(t *testing.T) {
	s, key, record, scope := signedOptionalFixture(t)
	rows, e := s.QuerySigned(context.Background(), scope, time.Now())
	if e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	base := rows[0]
	for _, name := range []string{"site", "key", "nil_key", "payload", "envelope", "previous_hash", "record_id", "signed_site", "day", "owner", "kind", "sequence", "unknown_field"} {
		t.Run(name, func(t *testing.T) {
			entry := Entry{base.Event, slices.Clone(base.Payload)}
			site, public := record.Site, key.Public().(ed25519.PublicKey)
			var p OptionalPayload
			if e := json.Unmarshal(entry.Payload, &p); e != nil {
				t.Fatal(e)
			}
			switch name {
			case "site":
				site = domain.NewID()
			case "key":
				public = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
			case "nil_key":
				public = nil
			case "previous_hash":
				entry.Event.PreviousSHA[0] ^= 1
			case "payload":
				p.Record.Status = 418
				entry.Payload, _ = json.Marshal(p)
			case "envelope":
				entry.Event.Signature = "bad"
			default:
				id, kind := entry.Event.RecordID, entry.Event.Kind
				switch name {
				case "record_id":
					id = domain.NewID()
				case "signed_site":
					p.Record.Site = domain.NewID()
				case "day":
					p.Day++
				case "owner":
					p.Owner = domain.NewID()
				case "kind":
					kind = "receipt"
				case "sequence":
					p.Seq = 0
				}
				entry.Payload, _ = json.Marshal(p)
				if name == "unknown_field" {
					entry.Payload = append(entry.Payload[:len(entry.Payload)-1], []byte(`,"secret":"should-not-pass"}`)...)
				}
				entry.Event, e = Seal(Source{p.Owner, uint64(p.Day), uint64(p.Seq)}, id, kind, entry.Payload, base.Event.PreviousSHA, 10, key)
				if name == "sequence" {
					if e == nil {
						t.Fatal("invalid source signed")
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e := VerifyOptionalEntry(entry, site, public); e == nil {
				t.Fatal("invalid copy accepted")
			}
		})
	}
}

func TestOptionalSignedQueryScopeAndStoppedOwner(t *testing.T) {
	s, _, record, scope := signedOptionalFixture(t)
	other := record
	other.ID = domain.NewID()
	board := domain.NewID()
	other.Board = &board
	if e := s.Write(context.Background(), other); e != nil {
		t.Fatal(e)
	}
	rows, e := s.QuerySigned(context.Background(), scope, time.Now())
	if e != nil || len(rows) != 1 || rows[0].Event.RecordID != record.ID {
		t.Fatal(len(rows), e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, e := s.QuerySigned(ctx, scope, time.Now()); !errors.Is(e, context.Canceled) || rows != nil {
		t.Fatal(rows, e)
	}
	day, _ := strconv.ParseUint(time.Unix(0, int64(record.Received)).UTC().Format("20060102"), 10, 64)
	s.journals[day].stopped = true
	if rows, e := s.QuerySigned(context.Background(), scope, time.Now()); e == nil || rows != nil {
		t.Fatal("stopped owner disclosed", rows, e)
	}
}

// 固定集合の上限を越えた場合、署名付き経路も先頭部分だけの成功にしない。
func TestOptionalSignedQueryLimitAndPartialPrune(t *testing.T) {
	s, key, record, scope := signedOptionalFixture(t)
	for i := 1; i < MaxOptionalQueryRecords; i++ {
		record.ID = domain.NewID()
		if e := s.Write(context.Background(), record); e != nil {
			t.Fatal(e)
		}
	}
	rows, e := s.QuerySigned(context.Background(), scope, time.Now())
	if e != nil || len(rows) != MaxOptionalQueryRecords {
		t.Fatal(len(rows), e)
	}
	record.ID = domain.NewID()
	if e := s.Write(context.Background(), record); e != nil {
		t.Fatal(e)
	}
	if rows, e := s.QuerySigned(context.Background(), scope, time.Now()); !errors.Is(e, ErrOptionalQueryLimit) || rows != nil {
		t.Fatal("partial overflow", len(rows), e)
	}
	// 満了対象だけを回収し、残るseq=102の署名を元sourceのまま照合する。
	live := record
	live.ID = domain.NewID()
	live.Received = record.Received + domain.Time(time.Minute)
	live.Finished, live.Until = live.Received+100, live.Received+domain.Time(OptionalRetention)
	if e := s.Write(context.Background(), live); e != nil {
		t.Fatal(e)
	}
	fixed := scope
	fixed.To = live.Received + 1000
	fixed.Records = []domain.ID{live.ID}
	selected, err := s.QuerySigned(context.Background(), fixed, time.Now())
	if err != nil || len(selected) != 1 || selected[0].Event.RecordID != live.ID {
		t.Fatal("fixed resume scope widened", len(selected), err)
	}
	fixed.Records = append(fixed.Records, live.ID)
	if _, err := s.QuerySigned(context.Background(), fixed, time.Now()); !errors.Is(err, ErrOptionalQueryScope) {
		t.Fatal("duplicate fixed IDs accepted", err)
	}
	cutoff := time.Unix(0, int64(record.Until))
	if _, e := s.Sweep(cutoff); e != nil {
		t.Fatal(e)
	}
	scope.To = live.Received + 1000
	rows, e = s.QuerySigned(context.Background(), scope, cutoff)
	if e != nil || len(rows) != 1 {
		t.Fatal(len(rows), e)
	}
	got, e := VerifyOptionalEntry(rows[0], live.Site, key.Public().(ed25519.PublicKey))
	if e != nil || got.Record.ID != live.ID || got.SourceSeq != 102 {
		t.Fatal(got, e)
	}
}
