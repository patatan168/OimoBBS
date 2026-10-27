// 実Cookie/キャップ投稿の受理原本から秘密なしの主体項目を提出できることを検査する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"maps"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"slices"
	"testing"
)

func assertAnonymousPrincipalProjection(t *testing.T, repo *Repository, board domain.ID, subject domain.Hash, cookie string) {
	t.Helper()
	rows, e := app.AcceptedRecords(slices.Collect(maps.Values(repo.posting[board].journals)))
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		selected, e := row.Project([]string{"connection"})
		if e != nil {
			t.Fatal(e)
		}
		principal := selected["cookie"].(map[string]any)
		if principal["id"] != subject {
			continue
		}
		if principal["status"] != "valid" {
			t.Fatal("Cookie validation status omitted")
		}
		submitted, err := disclosure.SubmissionRecords([]map[string]any{selected})
		if err != nil {
			t.Fatal(err)
		}
		value := submitted[0]["cookie"].(map[string]any)
		if value["id"] != subject.String() || value["status"] != "valid" {
			t.Fatal("saved Cookie identifier lost", value)
		}
		for _, key := range []string{"record_id", "operation_id", "board_id", "principal"} {
			if _, exists := submitted[0][key]; exists {
				t.Fatal("internal identifier exported", key)
			}
		}
		assertPrincipalSecretAbsent(t, submitted[0], cookie)
		unselected, err := row.Project([]string{"content"})
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := unselected["cookie"]; exists {
			t.Fatal("Cookie identifier disclosed without connection selection")
		}
		return
	}
	t.Fatal("accepted Cookie subject omitted")
}

func assertCapPrincipalProjection(t *testing.T, repo *Repository, board, id domain.ID, secret string) {
	t.Helper()
	rows, e := app.AcceptedRecords(slices.Collect(maps.Values(repo.posting[board].journals)))
	if e != nil || len(rows) == 0 {
		t.Fatal("accepted cap records", e)
	}
	selected, e := rows[0].Project([]string{"connection"})
	if e != nil {
		t.Fatal(e)
	}
	principal := selected["cookie"].(map[string]any)
	if principal["cap_id"] != nil || principal["cap_revision"] != nil {
		t.Fatal("internal qualification exported", principal)
	}
	assertPrincipalSecretAbsent(t, selected, secret)
}

func assertPrincipalSecretAbsent(t *testing.T, selected map[string]any, secret string) {
	t.Helper()
	raw, e := json.Marshal(selected)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("reusable credential disclosed")
	}
}
