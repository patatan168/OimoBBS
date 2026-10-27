// 実HTTPで生成したキャップ捕捉から旧表示のfixtureを組み立て、両形式を混同せず検証する。
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"testing"
)

// checkLegacyCapCapture は旧DATの長さ・frame・hashを同時に揃え、復旧の旧形式互換性を確認する。
func checkLegacyCapCapture(t *testing.T, capture, frame []byte, key uint64) {
	t.Helper()
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(capture, &fields); e != nil {
		t.Fatal(e)
	}
	if string(fields["renderer_profile"]) != `"dat-cap-v2"` {
		t.Fatal("new cap renderer missing")
	}
	fields["renderer_profile"] = json.RawMessage(`"dat-v1"`)
	mismatched, _ := json.Marshal(fields)
	if postcapture.ValidateFrame(mismatched, frame, key) == nil {
		t.Fatal("renderer mismatch accepted")
	}
	f, _, e := store.ReadFrame(bytes.NewReader(frame))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	if op.Type != "create" {
		t.Fatal("expected create")
	}
	var create domain.Create
	if e = json.Unmarshal(op.Payload, &create); e != nil {
		t.Fatal(e)
	}
	old, e := compat.LegacyDAT(create.Posts[0], create.Title)
	if e != nil {
		t.Fatal(e)
	}
	create.Posts[0].DATLength = uint32(len(old))
	op.After.DATBytes = domain.U64(len(old))
	op.Payload, _ = json.Marshal(create)
	f.Records[0].JSON, _ = json.Marshal(op)
	f.Records[0].DAT = old
	oldFrame, e := store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	fields["dat_sha256"], _ = json.Marshal(domain.Hash(sha256.Sum256(old)))
	fields["frame_sha256"], _ = json.Marshal(domain.Hash(sha256.Sum256(oldFrame)))
	legacy, _ := json.Marshal(fields)
	if e = postcapture.ValidateFrame(legacy, oldFrame, key); e != nil {
		t.Fatal("legacy capture", e)
	}
	fields["renderer_profile"] = json.RawMessage(`"dat-cap-v2"`)
	mismatched, _ = json.Marshal(fields)
	if postcapture.ValidateFrame(mismatched, oldFrame, key) == nil {
		t.Fatal("legacy dat accepted as new renderer")
	}
}
