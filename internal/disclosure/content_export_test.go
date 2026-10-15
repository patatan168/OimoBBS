// content選択の署名ZIPが入力・確定DATを区別し、非公開構造を出さないことを検査する。
package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"os"
	"testing"
)

func TestContentExportIncludesCommittedDAT(t *testing.T) {
	s, key, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "content-create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "content-hold", "保全", []app.AcceptedEvidence{record}, now)
	if e != nil {
		t.Fatal(e)
	}
	c, v, e := s.Generate(c.ID, actor, c.ETag(), "content-export", "提出", []string{"content"}, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal(e)
	}
	assertExportedContent(t, zipRecords(t, raw))
}

func assertExportedContent(t *testing.T, raw []byte) {
	t.Helper()
	var row struct {
		Content struct {
			Body  string      `json:"body"`
			DAT   []byte      `json:"dat_base64"`
			SHA   domain.Hash `json:"dat_sha256"`
			Posts []struct {
				Body string `json:"body"`
			} `json:"public_posts"`
		} `json:"content"`
	}
	if e := json.Unmarshal(raw, &row); e != nil {
		t.Fatal(e)
	}
	expected := []byte("public-name<>sage<>date<>PUBLIC_BODY<>public-title\n")
	if row.Content.Body != "PRIVATE_BODY" || !bytes.Equal(row.Content.DAT, expected) || row.Content.SHA != sha256.Sum256(expected) || len(row.Content.Posts) != 1 || row.Content.Posts[0].Body != "PUBLIC_BODY" {
		t.Fatal("input and committed public part not separated")
	}
	for _, secret := range []string{"SECRET_CREDENTIAL", "PRIVATE_CONNECTION_SECRET", `"private"`, "prepared_frame_base64"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret in ZIP", secret)
		}
	}
}
