// 実HTTP案件照会のcontentが、保全した原本の確定DATを秘密なしで返すことを検査する。
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
)

func assertSelectedAcceptedDAT(t *testing.T, raw, proposal json.RawMessage) {
	t.Helper()
	var rows []struct {
		Content struct {
			DAT   []byte            `json:"dat_base64"`
			SHA   domain.Hash       `json:"dat_sha256"`
			Posts []json.RawMessage `json:"public_posts"`
		} `json:"content"`
	}
	if e := json.Unmarshal(raw, &rows); e != nil || len(rows) != 1 {
		t.Fatal("content rows", e)
	}
	dat := originalContentDAT(t, proposal)
	if !bytes.Equal(rows[0].Content.DAT, dat) || rows[0].Content.SHA != sha256.Sum256(dat) || len(rows[0].Content.Posts) != 1 {
		t.Fatal("committed content correspondence")
	}
	for _, secret := range []string{"trip-secret-to-remove", "unknown-secret-to-remove", `"private"`, `"source_ip"`, `"rate_keys"`, "prepared_frame_base64"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret in selected content", secret)
		}
	}
}

func originalContentDAT(t *testing.T, proposal json.RawMessage) []byte {
	t.Helper()
	var original struct {
		Frame string `json:"prepared_frame_base64"`
	}
	if e := json.Unmarshal(proposal, &original); e != nil {
		t.Fatal(e)
	}
	frame, e := base64.StdEncoding.Strict().DecodeString(original.Frame)
	if e != nil {
		t.Fatal(e)
	}
	f, _, e := store.ReadFrame(bytes.NewReader(frame))
	if e != nil || len(f.Records) != 1 {
		t.Fatal("original frame", e)
	}
	return f.Records[0].DAT
}
