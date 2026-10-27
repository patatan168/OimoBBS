// 1MiBを超えるsnapshotのZstandard復号と、旧gzip codecの拒否を検査する。
package store

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"oimobbs/internal/domain"
	"reflect"
	"strings"
	"testing"
)

func TestControlSnapshotLargeZstdAndLegacyRejection(t *testing.T) {
	var owner domain.ID
	owner[0] = 7
	h := Header{Kind: 2, Owner: owner, Generation: 2, BaseSeq: 2}
	value, _ := json.Marshal(map[string]string{"last_reserved_key": "1792195200", "padding": strings.Repeat("synthetic snapshot data ", 40000)})
	state := ControlState{Seq: 2, Rows: map[string]ControlRow{
		"key_watermark:a": {Revision: 1, Value: value},
		"key_watermark:b": {Revision: 2, Value: value},
	}}
	validate := func(string, string, json.RawMessage, json.RawMessage) error { return nil }
	raw, err := EncodeControlSnapshot(h, state, 6, validate)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw[:8]) != "OIMOCSN2" || raw[84] != 2 || le.Uint32(raw[72:]) <= 1<<20 {
		t.Fatal("large Zstandard chunk not exercised")
	}
	got, err := DecodeControlSnapshot(raw, h, validate)
	if err != nil || !reflect.DeepEqual(got, state) {
		t.Fatal("large snapshot roundtrip", err)
	}
	plain, err := EncodeControlSnapshot(h, state, 0, validate)
	if err != nil {
		t.Fatal(err)
	}
	legacy := bytes.Clone(plain)
	copy(legacy, "OIMOCSN1")
	le.PutUint16(legacy[8:], 1)
	le.PutUint32(legacy[60:], checksum(legacy[:60]))
	if _, err := DecodeControlSnapshot(legacy, h, validate); err == nil {
		t.Fatal("legacy snapshot accepted")
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	_, err = w.Write(plain[96:])
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	legacy = append(bytes.Clone(plain[:96]), compressed.Bytes()...)
	legacy[84] = 1
	legacy[85] = 6
	le.PutUint32(legacy[76:], uint32(compressed.Len()))
	le.PutUint32(legacy[92:], checksum(compressed.Bytes()))
	if _, err := DecodeControlSnapshot(legacy, h, validate); err == nil {
		t.Fatal("gzip compatibility remained")
	}
}
