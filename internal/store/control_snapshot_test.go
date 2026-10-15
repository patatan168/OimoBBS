// 設計fixtureと実fileでsnapshot復旧・delta追記・破損拒否を確認する。
package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func snapshotFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	raw, e := os.ReadFile("../../docs/design/fixtures/control-v1-layout.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Snapshot string `json:"snapshot_hex"`
		Delta    string `json:"empty_delta_hex"`
		Current  string `json:"current_utf8"`
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	snap, e := hex.DecodeString(fixture.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	delta, e := hex.DecodeString(fixture.Delta)
	if e != nil {
		t.Fatal(e)
	}
	return snap, delta, []byte(fixture.Current)
}
func snapshotValidator(collection, key string, old, next json.RawMessage) error {
	if collection != "key_watermark" || key != "thread" || !json.Valid(next) {
		return ErrCorrupt
	}
	return nil
}
func TestControlSnapshotFixtureAndReplay(t *testing.T) {
	snap, delta, current := snapshotFixture(t)
	h, e := DecodeHeader(delta)
	if e != nil {
		t.Fatal(e)
	}
	state, e := DecodeControlSnapshot(snap, h, snapshotValidator)
	if e != nil || state.Seq != 2 || state.Rows["key_watermark:thread"].Revision != 2 {
		t.Fatal(state, e)
	}
	for _, level := range []int{0, 1, 6, 9} {
		encoded, e := EncodeControlSnapshot(h, state, level, snapshotValidator)
		if e != nil {
			t.Fatal(e)
		}
		restored, e := DecodeControlSnapshot(encoded, h, snapshotValidator)
		if e != nil || !reflect.DeepEqual(state, restored) {
			t.Fatal(level, e)
		}
		if level == 0 && !bytes.Equal(encoded, snap) {
			t.Fatal("fixture encoding differs")
		}
	}
	dir := privateTemp(t)
	for name, raw := range map[string][]byte{"control.current": current, "control-000003.snap": snap, "control-000003.wal": delta} {
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	log, e := OpenControl(dir, 2, h.Owner, 0, snapshotValidator)
	if e != nil {
		t.Fatal(e)
	}
	op := ControlOperation{Schema: 1, Seq: 3, ExpectedSeq: 2, Actor: domain.Actor{Kind: "system", Reason: "reserve_key"}, Mutations: []Mutation{{Collection: "key_watermark", Key: "thread", ExpectedRevision: 2, Value: json.RawMessage(`{"last_reserved_key":"1790492402"}`)}}, Result: ControlResult{Code: "reserved", Targets: []string{}}}
	raw, _ := json.Marshal(op)
	frame, _ := EncodeFrame(Frame{FirstSeq: 3, Records: []Record{{ID: domain.NewID(), JSON: raw}}})
	if log.Append(frame).Status != Durable {
		t.Fatal("append after snapshot")
	}
	budget := HistoryBudget{1 << 20, 100}
	if e = log.VisitCommitted(context.Background(), &budget, func(Record, ControlOperation) error { return nil }); !errors.Is(e, ErrHistoryCompacted) {
		t.Fatal("partial history reported as complete", e)
	}
	log.Close()
	restored, e := InspectControl(dir, 2, h.Owner, 0, snapshotValidator)
	if e != nil || restored.Seq != 3 || restored.Rows["key_watermark:thread"].Revision != 3 {
		t.Fatal(restored, e)
	}
	// SHA不一致をsnapshotの切詰め修復として扱わない。
	snap[len(snap)-1] ^= 1
	if e = os.WriteFile(filepath.Join(dir, "control-000003.snap"), snap, 0600); e != nil {
		t.Fatal(e)
	}
	if log, e = OpenControl(dir, 2, h.Owner, 0, snapshotValidator); e == nil {
		log.Close()
		t.Fatal("bad snapshot accepted")
	}
}

func TestControlSnapshotRejectsMalformedChunksAndRows(t *testing.T) {
	snap, delta, _ := snapshotFixture(t)
	h, _ := DecodeHeader(delta)
	raw := bytes.Clone(snap[96:])
	makeSnapshot := func(chunks ...[]byte) []byte {
		b := bytes.Clone(snap[:64])
		le.PutUint32(b[56:], uint32(len(chunks)))
		le.PutUint32(b[60:], checksum(b[:60]))
		for _, chunk := range chunks {
			b = append(b, chunk...)
		}
		return b
	}
	baseChunk, _ := encodeSnapshotChunk(raw, 1, 0)
	gzipChunk, _ := encodeSnapshotChunk(raw, 1, 6)
	invalid := map[string][]byte{
		"truncated": snap[:len(snap)-1], "trailing": append(bytes.Clone(snap), 0),
		"duplicate_across_chunks": makeSnapshot(baseChunk, baseChunk),
	}
	for name, change := range map[string]func([]byte){
		"raw_crc":    func(b []byte) { b[24] ^= 1 },
		"stored_crc": func(b []byte) { b[28] ^= 1 },
		"reserved":   func(b []byte) { b[22] = 1 },
		"codec":      func(b []byte) { b[20] = 2 },
		"raw_level":  func(b []byte) { b[21] = 6 },
		"rows":       func(b []byte) { le.PutUint32(b[16:], 2) },
		"huge_raw":   func(b []byte) { le.PutUint32(b[8:], maxSnapshotChunk+1) },
	} {
		chunk := bytes.Clone(baseChunk)
		change(chunk)
		invalid[name] = makeSnapshot(chunk)
	}
	for name, tail := range map[string][]byte{"multiple_members": gzipChunk[32:], "gzip_trailing": {0}} {
		chunk := append(bytes.Clone(gzipChunk), tail...)
		le.PutUint32(chunk[12:], uint32(len(chunk)-32))
		le.PutUint32(chunk[28:], checksum(chunk[32:]))
		invalid[name] = makeSnapshot(chunk)
	}
	undersized := bytes.Clone(gzipChunk)
	le.PutUint32(undersized[8:], uint32(len(raw)-1))
	invalid["expansion_overrun"] = makeSnapshot(undersized)
	var original snapshotRow
	if e := json.Unmarshal(raw[4:], &original); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*snapshotRow){
		"future_revision":    func(r *snapshotRow) { r.Revision = 3 },
		"zero_revision":      func(r *snapshotRow) { r.Revision = 0 },
		"unknown_collection": func(r *snapshotRow) { r.Collection = "unknown" },
		"null_value":         func(r *snapshotRow) { r.Value = json.RawMessage(`null`) },
		"invalid_key":        func(r *snapshotRow) { r.Key = "../thread" },
	} {
		row := original
		change(&row)
		encoded, _ := json.Marshal(row)
		body := le.AppendUint32(nil, uint32(len(encoded)))
		body = append(body, encoded...)
		chunk, _ := encodeSnapshotChunk(body, 1, 0)
		invalid[name] = makeSnapshot(chunk)
	}
	for name, b := range invalid {
		t.Run(name, func(t *testing.T) {
			state, e := DecodeControlSnapshot(b, h, snapshotValidator)
			if e == nil || state.Rows != nil {
				t.Fatal("partial or invalid snapshot accepted", e)
			}
		})
	}
	wrong := h
	wrong.Owner = domain.NewID()
	if _, e := DecodeControlSnapshot(snap, wrong, snapshotValidator); e == nil {
		t.Fatal("wrong owner")
	}
	if _, e := DecodeControlSnapshot(snap, h, func(string, string, json.RawMessage, json.RawMessage) error {
		return errors.New("invalid business value")
	}); e == nil {
		t.Fatal("value validation bypassed")
	}
}

func TestControlSnapshotPreservesExpiryAndEmptyState(t *testing.T) {
	h := Header{Kind: 1, Owner: domain.NewID(), BaseSeq: 7, Generation: 2}
	expires := domain.Time(123)
	state := ControlState{Seq: 7, Rows: map[string]ControlRow{"admin_receipt:test": {Revision: 4, Expires: &expires, Value: json.RawMessage(`{"retained":true}`)}}}
	validate := func(string, string, json.RawMessage, json.RawMessage) error { return nil }
	for _, level := range []int{0, 1, 6, 9} {
		raw, e := EncodeControlSnapshot(h, state, level, validate)
		if e != nil {
			t.Fatal(e)
		}
		got, e := DecodeControlSnapshot(raw, h, validate)
		if e != nil || !reflect.DeepEqual(got, state) {
			t.Fatal("expiry or revision changed", e)
		}
	}
	state.Rows = map[string]ControlRow{}
	raw, e := EncodeControlSnapshot(h, state, 0, validate)
	if e != nil || len(raw) != 64 {
		t.Fatal(e)
	}
	got, e := DecodeControlSnapshot(raw, h, validate)
	if e != nil || !reflect.DeepEqual(got, state) {
		t.Fatal(e)
	}
}
