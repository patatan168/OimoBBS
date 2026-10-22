// content選択の署名ZIPが入力・確定DATを区別し、非公開構造を出さないことを検査する。
package disclosure

import (
	"bytes"
	"crypto/ed25519"
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
	assertSubmissionReadme(t, raw)
	// 終了案内を提出せず、署名付きmanifestの件数も本人の投稿行だけになる。
	manifest, e := VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	projected := []map[string]any{{"source_event_sha256": "source", "thread_key": "123", "content": map[string]any{"body": "入力", "public_posts": []any{
		map[string]any{"number": 8, "kind": "user", "name": "本人", "body": "入力"}, map[string]any{"number": 9, "kind": "system", "name": "終了案内", "body": "AUTO_END_SECRET"},
	}}}}
	manifest.Files = nil
	if e = s.writeProjectedZIP(c, v, manifest, projected, nil); e != nil {
		t.Fatal(e)
	}
	raw, e = os.ReadFile(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	manifest, e = VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key.Public().(ed25519.PublicKey))
	if e != nil || manifest.Count != 1 {
		t.Fatal("user-only CSV signed count", manifest.Count, e)
	}
	assertSubmissionReadme(t, raw)
	if bytes.Contains(zipRecords(t, raw), []byte("AUTO_END_SECRET")) {
		t.Fatal("automatic post exported")
	}
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
	if row.Content.Body != "PRIVATE_BODY" || row.Content.DAT != nil || row.Content.SHA != (domain.Hash{}) || len(row.Content.Posts) != 1 || row.Content.Posts[0].Body != "" {
		t.Fatal("input and committed public part not separated")
	}
	for _, secret := range []string{"SECRET_CREDENTIAL", "PRIVATE_CONNECTION_SECRET", `"private"`, "prepared_frame_base64"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret in ZIP", secret)
		}
	}
}
