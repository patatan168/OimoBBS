// 実Cookie/キャップ投稿の受理原本から秘密なしの主体項目を提出できることを検査する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"maps"
	"oimobbs/internal/app"
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
		selected, e := row.Project([]string{"principal"})
		if e != nil {
			t.Fatal(e)
		}
		principal := selected["principal"].(map[string]any)
		if principal["anon_subject_hmac"] != subject {
			continue
		}
		if principal["hmac_key_id"] != nil {
			t.Fatal("subject key ID inferred from admission key")
		}
		assertPrincipalSecretAbsent(t, selected, cookie)
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
	selected, e := rows[0].Project([]string{"principal"})
	if e != nil {
		t.Fatal(e)
	}
	principal := selected["principal"].(map[string]any)
	if principal["cap_id"] != id || principal["cap_revision"] != domain.U64(1) {
		t.Fatal("accepted qualification omitted", principal)
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
