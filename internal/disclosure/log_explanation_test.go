// 説明が署名ZIPのファイルhashに含まれ、提出済み説明が後の状態で変わらないことを検査する。
package disclosure

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"oimobbs/internal/app"
	"os"
	"strings"
	"testing"
)

func TestLogExplanationFailureLeavesResumableIntent(t *testing.T) {
	s, _, c, actor, now, rows := rejectedExportFixture(t)
	stop := errors.New("explanation unavailable")
	s.SetLogExplanation(func(Scope) (string, error) { return "", stop })
	etag := c.ETag()
	c, _, e := s.GenerateRejected(c.ID, actor, etag, "failed-explanation", "提出", nil, rows, now)
	if !errors.Is(e, stop) || len(c.Exports) != 1 || c.Exports[0].State != "preparing" {
		t.Fatal(c, e)
	}
	if _, e = os.Stat(s.exportPath(c.ID, c.Exports[0].ID)); !os.IsNotExist(e) {
		t.Fatal("ZIP completed without explanation", e)
	}
	s.SetLogExplanation(func(Scope) (string, error) { return "未確認期間あり。", nil })
	_, v, e := s.GenerateRejected(c.ID, actor, etag, "failed-explanation", "提出", nil, rows, now)
	if e != nil || v.State != "ready" {
		t.Fatal(v, e)
	}
}

func TestLogExplanationSignedRejectedZIP(t *testing.T) {
	s, key, c, actor, now, rows := rejectedExportFixture(t)
	s.SetLogExplanation(func(scope Scope) (string, error) {
		if scope.Board != c.Scope.Board {
			t.Fatal("scope changed")
		}
		return "固定境界の欠落・照合失敗 1日。未確認期間の件数は不明です。", nil
	})
	etag := c.ETag()
	c, v, e := s.GenerateRejected(c.ID, actor, etag, "gap-zip", "確認状況付き提出", nil, rows, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	m, e := VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key.Public().(ed25519.PublicKey))
	if e != nil || m.Completeness != "partial" || len(m.Files) != 3 {
		t.Fatal(m, e)
	}
	text := explanationZIPReadme(t, raw)
	if !strings.Contains(text, "照合失敗 1日") || !strings.Contains(text, "missing_record_ids") {
		t.Fatal(text)
	}
	s.SetLogExplanation(func(Scope) (string, error) { return "後の状態", nil })
	_, _, e = s.GenerateRejected(c.ID, actor, etag, "gap-zip", "確認状況付き提出", nil, rows, now)
	if e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadFile(s.exportPath(c.ID, v.ID))
	if e != nil || !bytes.Equal(raw, after) {
		t.Fatal("ready ZIP changed", e)
	}
}

func TestLogExplanationDefaultAcceptedZIP(t *testing.T) {
	s, key, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "case", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "hold", "保全", []app.AcceptedEvidence{record}, now)
	if e != nil {
		t.Fatal(e)
	}
	c, v, e := s.Generate(c.ID, actor, c.ETag(), "zip", "提出", nil, now)
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
	if text := explanationZIPReadme(t, raw); !strings.Contains(text, "ログの確認状況：未確認") {
		t.Fatal(text)
	}
}

// explanationZIPReadme は署名対象の説明ファイルだけを試験で読む。
func explanationZIPReadme(t *testing.T, raw []byte) string {
	t.Helper()
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range z.File {
		if file.Name != "readme.txt" {
			continue
		}
		r, e := file.Open()
		if e != nil {
			t.Fatal(e)
		}
		data, e := io.ReadAll(r)
		_ = r.Close()
		if e != nil {
			t.Fatal(e)
		}
		return string(data)
	}
	t.Fatal("readme missing")
	return ""
}
