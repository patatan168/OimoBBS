// 管理HTTPの主体選択が受理原本の投稿枠ルール集合と一致することを検査する。
package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"testing"
)

func assertSelectedAcceptedRules(t *testing.T, raw, proposal json.RawMessage) {
	t.Helper()
	var rows []struct {
		Principal struct {
			Rules []domain.ID `json:"rule_ids"`
		} `json:"principal"`
	}
	if e := json.Unmarshal(raw, &rows); e != nil || len(rows) != 1 {
		t.Fatal("principal rows", e)
	}
	wanted := originalAcceptedRules(t, proposal)
	got := rows[0].Principal.Rules
	if got == nil || len(got) != len(wanted) {
		t.Fatal("saved admission rules omitted", string(raw))
	}
	for _, id := range got {
		if !wanted[id] {
			t.Fatal("rule not bound to original or duplicated", id)
		}
		delete(wanted, id)
	}
	for _, secret := range []string{`"content"`, `"connection"`, `"private"`, `"source_ip"`, `"rate_keys"`, "PRIVATE-POST-BODY", "trip-secret-to-remove", "prepared_frame_base64", "optional_http"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("unselected data in principal query", secret)
		}
	}
}

func originalAcceptedRules(t *testing.T, proposal json.RawMessage) map[domain.ID]bool {
	t.Helper()
	var p struct {
		Frame string `json:"prepared_frame_base64"`
	}
	if e := json.Unmarshal(proposal, &p); e != nil {
		t.Fatal(e)
	}
	decoded, e := base64.StdEncoding.Strict().DecodeString(p.Frame)
	if e != nil {
		t.Fatal(e)
	}
	f, _, e := store.ReadFrame(bytes.NewReader(decoded))
	if e != nil || len(f.Records) != 1 {
		t.Fatal("original frame", e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	var payload struct {
		Posts []domain.Post `json:"posts"`
	}
	if e = json.Unmarshal(op.Payload, &payload); e != nil {
		t.Fatal(e)
	}
	wanted := map[domain.ID]bool{}
	for _, post := range payload.Posts {
		if post.Private == nil {
			continue
		}
		for _, key := range post.Private.RateKeys {
			wanted[key.Rule] = true
		}
	}
	return wanted
}
