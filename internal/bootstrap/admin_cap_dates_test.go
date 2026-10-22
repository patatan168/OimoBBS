// 新HTTP期限のRFC3339Nanoと旧ns要求の互換性、排他的な厳密入力を確認する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"testing"
	"time"
)

func TestAdminCapDateContract(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, err := r.CreateBoard(t.Context(), "dates", "期限確認")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	at := time.Now().Add(time.Hour).Round(time.Millisecond).UTC()
	input := map[string]any{"display_name": "期限確認", "board_ids": []domain.ID{board.ID}, "permissions": []string{"post"}, "expires_at": at.Format(time.RFC3339Nano)}
	list, _ := c.request("GET", "/api/v1/caps", "", nil)
	raw, _ := json.Marshal(input)
	res, body := c.request("POST", "/api/v1/caps", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {list.Header.Get("ETag")}, "X-CSRF-Token": {list.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal("RFC3339 input", res.StatusCode, body)
	}
	var result struct {
		Data capHTTPView `json:"data"`
	}
	if json.Unmarshal([]byte(body), &result) != nil || result.Data.ExpiresAt != at.Format(time.RFC3339Nano) || result.Data.Expires != domain.Time(at.UnixNano()) {
		t.Fatal("HTTP date")
	}
	res, body = c.request("GET", "/api/v1/caps/"+result.Data.ID.String(), "", nil)
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &result) != nil || result.Data.ExpiresAt != at.Format(time.RFC3339Nano) {
		t.Fatal("detail date")
	}
	input["expires_at_ns"] = domain.Time(at.UnixNano())
	raw, _ = json.Marshal(input)
	var decoded capInput
	if strictjson.Decode(raw, &decoded) == nil {
		t.Fatal("ambiguous date")
	}
	delete(input, "expires_at")
	raw, _ = json.Marshal(input)
	if strictjson.Decode(raw, &decoded) != nil || decoded.Expires != domain.Time(at.UnixNano()) {
		t.Fatal("legacy date")
	}
	delete(input, "expires_at_ns")
	for _, date := range []any{nil, "2026-01-01", "2500-01-01T00:00:00Z", "1960-01-01T00:00:00Z", 10} {
		input["expires_at"] = date
		raw, _ = json.Marshal(input)
		if strictjson.Decode(raw, &decoded) == nil {
			t.Fatal("invalid date", date)
		}
	}
}
