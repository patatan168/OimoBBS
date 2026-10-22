// 証拠管理の日時互換入力、精度、固定再送、厳密な不正入力拒否を検査する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestEvidenceRequestDateCompatibility(t *testing.T) {
	at := time.Date(2026, 10, 6, 0, 1, 2, 123456789, domain.JST)
	legacy := evidenceInput{Until: domain.Time(at.UnixNano()), Scope: disclosure.Scope{Board: domain.NewID(), From: domain.Time(at.Add(-time.Hour).UnixNano()), To: domain.Time(at.UnixNano())}}
	want, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	modern := map[string]any{"hold_until": at.Format(time.RFC3339Nano), "scope": map[string]any{"board_id": legacy.Scope.Board, "from": at.Add(-time.Hour).UTC().Format(time.RFC3339Nano), "to": at.Format(time.RFC3339Nano)}}
	raw, _ := json.Marshal(modern)
	for _, input := range [][]byte{raw, want} {
		var decoded evidenceInput
		if err := decodeEvidenceInput(input, &decoded); err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(decoded)
		if !bytes.Equal(got, want) {
			t.Fatal("date normalization changed request", string(got), string(want))
		}
	}
}

func TestEvidenceRequestDateRejections(t *testing.T) {
	for _, raw := range []string{
		`{"hold_until":null}`, `{"hold_until":123}`, `{"hold_until":""}`,
		`{"hold_until":"2026-10-06"}`, `{"hold_until":"1960-01-01T00:00:00Z"}`, `{"hold_until":"2500-01-01T00:00:00Z"}`,
		`{"hold_until":"2026-10-06T00:00:00Z","hold_until_ns":"0"}`,
		`{"scope":{"from":"2026-10-06T00:00:00Z","from_ns":"0"}}`,
		`{"scope":{"to":"2026-10-06T00:00:00Z","to_ns":"0"}}`,
		`{"transfer":{"transferred_at":"2026-10-06T00:00:00Z","transferred_at_ns":"0"}}`,
		`{"scope":{"from":"2026-10-06T00:00:00Z","from":"2026-10-07T00:00:00Z"}}`,
		`{"hold_until":"2026-10-06T00:00:00Z","hold_until":"2026-10-07T00:00:00Z"}`,
		`{"scope":{"from":"2026-10-06T00:00:00Z","unknown":true}}`,
		`{"transfer":{"transferred_at":"2026-10-06T00:00:00Z","unknown":true}}`,
		`{"hold_until":"2026-10-06T00:00:00Z","unknown":true}`, `{"scope":[]}`,
	} {
		var decoded evidenceInput
		if err := decodeEvidenceInput([]byte(raw), &decoded); err == nil {
			t.Fatal("invalid or ambiguous dates accepted", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"hold_until_ns":"0"}`, `{"hold_until":"1970-01-01T00:00:00Z"}`, `{"scope":null}`} {
		var decoded evidenceInput
		if err := decodeEvidenceInput([]byte(raw), &decoded); err != nil {
			t.Fatal("legacy default rejected", raw, err)
		}
	}
}

// TestEvidenceRemovedColumnSelection は削除した項目選択を空指定も含めて拒否する。
func TestEvidenceRemovedColumnSelection(t *testing.T) {
	for _, raw := range []string{`{"columns":null}`, `{"columns":[]}`, `{"columns":["connection"]}`, `{"columns":["content"]}`, `{"connection":true}`, `{"content":true}`} {
		var input evidenceInput
		if err := decodeEvidenceInput([]byte(raw), &input); err == nil {
			t.Fatal("removed selection accepted", raw)
		}
	}
}

func TestAdminEvidenceRFC3339CreateAndRetry(t *testing.T) {
	cfg, repo := adminFixture(t)
	board, err := repo.CreateBoard(t.Context(), "dates", "日時確認")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	now := time.Now().UTC()
	until := now.Add(24 * time.Hour)
	input := evidenceInput{Number: "DATE", Reason: "日時互換", Until: domain.Time(until.UnixNano()), Scope: disclosure.Scope{Board: board.ID, From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano())}}
	list, _ := c.request("GET", "/api/v1/evidence/cases", "", nil)
	modern := map[string]any{"case_number": input.Number, "reason": input.Reason, "hold_until": until.In(domain.JST).Format(time.RFC3339Nano), "scope": map[string]any{"board_id": board.ID, "from": now.Add(-time.Hour).Format(time.RFC3339Nano), "to": now.Format(time.RFC3339Nano)}}
	raw, _ := json.Marshal(modern)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {list.Header.Get("ETag")}, "X-Csrf-Token": {list.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"evidence-dates-create-01"}}
	res, body := c.request("POST", "/api/v1/evidence/cases", string(raw), headers)
	created := assertCreatedEvidenceDates(t, res, body, input)
	for _, path := range []string{"/api/v1/evidence/cases", "/api/v1/evidence/cases/" + created.ID.String()} {
		res, body := c.request("GET", path, "", nil)
		assertEvidenceCaseListDates(t, res, body, created)
	}
	res, retried, body := evidencePost(t, c, "/api/v1/evidence/cases", input, headers.Get("If-Match"), headers.Get("X-CSRF-Token"), headers.Get("Idempotency-Key"))
	if res.StatusCode != 200 || retried.ID != created.ID || retried.Until != created.Until {
		t.Fatal("legacy retry changed case", res.StatusCode, body)
	}
}

// assertCreatedEvidenceDates はHTTP入力が精度を保って案件保存値へ接続されたことを確認する。
func assertCreatedEvidenceDates(t *testing.T, res *http.Response, body string, input evidenceInput) disclosure.Case {
	t.Helper()
	var result struct {
		Data disclosure.Case `json:"data"`
	}
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &result) != nil {
		t.Fatal("RFC3339 create", res.StatusCode, body)
	}
	if result.Data.Until != input.Until || result.Data.Scope.From != input.Scope.From || result.Data.Scope.To != input.Scope.To {
		t.Fatal("date precision changed", body)
	}
	assertEvidenceCaseHTTPDates(t, []byte(body), result.Data)
	return result.Data
}

// assertEvidenceCaseHTTPDates は作成応答の日付別名が保存値と一致することを検査する。
func assertEvidenceCaseHTTPDates(t *testing.T, raw []byte, saved disclosure.Case) {
	t.Helper()
	var response struct {
		Data evidenceCaseHTTPView `json:"dates"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	assertEvidenceCaseViewDates(t, response.Data, saved)
}

func assertEvidenceCaseListDates(t *testing.T, res *http.Response, body string, saved disclosure.Case) {
	t.Helper()
	var response struct {
		Data []evidenceCaseHTTPView `json:"dates"`
	}
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &response) != nil || len(response.Data) != 1 {
		t.Fatal("case list dates", res.StatusCode, body)
	}
	assertEvidenceCaseViewDates(t, response.Data[0], saved)
}

func assertEvidenceCaseViewDates(t *testing.T, view evidenceCaseHTTPView, saved disclosure.Case) {
	t.Helper()
	if view.CreatedAt != adminDate(saved.Created) || view.HoldUntil != adminDate(saved.Until) || view.ClosedAt != nil {
		t.Fatal("case dates missing", view)
	}
	if view.Scope.From != adminDate(saved.Scope.From) || view.Scope.To != adminDate(saved.Scope.To) {
		t.Fatal("scope dates missing", view.Scope)
	}
}
