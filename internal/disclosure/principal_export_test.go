// 主体選択の署名ZIPが受理枠ルールを含み、本文と接続情報を含めないことを検査する。
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

func TestPrincipalExportIncludesRateRuleArray(t *testing.T) {
	s, key, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "principal-create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "principal-hold", "保全", []app.AcceptedEvidence{record}, now)
	if e != nil {
		t.Fatal(e)
	}
	c, v, e := s.Generate(c.ID, actor, c.ETag(), "principal-export", "提出", []string{"principal"}, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	assertPrincipalExportRules(t, raw, key.Public().(ed25519.PublicKey))
	assertExportedAcceptedMetadata(t, zipRecords(t, raw), record)
}

func assertPrincipalExportRules(t *testing.T, raw []byte, key ed25519.PublicKey) {
	t.Helper()
	if _, e := VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key); e != nil {
		t.Fatal(e)
	}
	records := zipRecords(t, raw)
	var row struct {
		Principal struct {
			Rules []domain.ID `json:"rule_ids"`
		} `json:"principal"`
	}
	if e := json.Unmarshal(records, &row); e != nil {
		t.Fatal(e)
	}
	if row.Principal.Rules == nil || len(row.Principal.Rules) != 0 {
		t.Fatal("no admission rule was saved; expected []", string(records))
	}
	for _, secret := range []string{`"content"`, `"connection"`, `"private"`, `"source_ip"`, "PUBLIC_BODY", "PRIVATE_BODY", "SECRET_CREDENTIAL", "PRIVATE_CONNECTION_SECRET", "prepared_frame_base64"} {
		if bytes.Contains(records, []byte(secret)) {
			t.Fatal("unselected data in ZIP", secret)
		}
	}
}
