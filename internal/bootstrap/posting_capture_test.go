// 実フォームの保存記録で、型検証・HMAC再計算・投稿内容との照合を別々に検査する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"testing"
)

func checkStoredFormCaptures(t *testing.T, repo *Repository, owner domain.ID) {
	t.Helper()
	b := repo.posting[owner]
	checked := 0
	testedCreate := false
	for _, j := range b.journals {
		for _, entry := range j.Entries() {
			if entry.Event.Kind != "evidence_proposal" {
				continue
			}
			var proposal struct {
				Capture json.RawMessage `json:"capture"`
				Frame   string          `json:"prepared_frame_base64"`
				Key     domain.U64      `json:"thread_key"`
			}
			if e := json.Unmarshal(entry.Payload, &proposal); e != nil {
				t.Fatal(e)
			}
			frame, e := base64.StdEncoding.DecodeString(proposal.Frame)
			if e != nil {
				t.Fatal(e)
			}
			var c postcapture.Capture
			if e = json.Unmarshal(proposal.Capture, &c); e != nil {
				t.Fatal(e)
			}
			if c.Schema != postcapture.Schema || c.Completeness != "partial" || c.TokenValidation != "not_checked" || c.Input.Body == "" || c.FrameSHA != sha256.Sum256(frame) {
				t.Fatal("incomplete form capture")
			}
			if e = postcapture.ValidateKey(proposal.Capture, b.dedupKey); e != nil {
				t.Fatal(e)
			}
			if e = app.PostingValidator(b.validate)("evidence_proposal", entry.Payload); e != nil {
				t.Fatal(e)
			}
			checked++
			if c.Target != 0 || testedCreate {
				continue
			}
			testedCreate = true
			for _, tc := range []struct {
				name   string
				change func(*postcapture.Capture)
			}{
				{"body", func(c *postcapture.Capture) {
					c.Input.Body = "取り違え"
					c.BodySHA = sha256.Sum256([]byte(c.Input.Body))
				}},
				{"name", func(c *postcapture.Capture) { c.Input.Name = "別の名前" }},
				{"trip", func(c *postcapture.Capture) { c.Input.Trip = "different" }},
				{"mail", func(c *postcapture.Capture) { c.Input.Mail = "sage" }},
				{"title", func(c *postcapture.Capture) { c.Input.Title = "別題" }},
				{"target", func(c *postcapture.Capture) { c.Target = 123 }},
				{"versions", func(c *postcapture.Capture) { c.Versions.Board++ }},
				{"subject", func(c *postcapture.Capture) { c.Dedup.Subject[0] ^= 1 }},
				{"request", func(c *postcapture.Capture) { c.Dedup.Request[0] ^= 1 }},
				{"dat_hash", func(c *postcapture.Capture) { c.DATSHA[0] ^= 1 }},
				{"frame_hash", func(c *postcapture.Capture) { c.FrameSHA[0] ^= 1 }},
				{"token_claim", func(c *postcapture.Capture) { c.TokenValidation = "verified" }},
				{"completeness", func(c *postcapture.Capture) { c.Completeness = "complete" }},
				{"secret_mail", func(c *postcapture.Capture) { c.Input.Mail = "#cap:id:secret" }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var bad postcapture.Capture
					json.Unmarshal(proposal.Capture, &bad)
					tc.change(&bad)
					raw, _ := json.Marshal(bad)
					if e := postcapture.ValidateFrame(raw, frame, uint64(proposal.Key)); e == nil {
						t.Fatal("capture/frame mismatch accepted")
					}
					// proposal型が正しくても、内容の照合を省略できない。
					var fields map[string]json.RawMessage
					json.Unmarshal(entry.Payload, &fields)
					fields["capture"] = raw
					payload, _ := json.Marshal(fields)
					if e := app.PostingValidator(postcapture.Validate)("evidence_proposal", payload); e == nil {
						t.Fatal("journal accepted mismatched capture")
					}
					result := repo.Post(context.Background(), owner, 0, frame, raw)
					if result.Status != store.NotWritten {
						t.Fatal("mismatch persisted", result)
					}
				})
			}
			var bad postcapture.Capture
			json.Unmarshal(proposal.Capture, &bad)
			bad.Input.Credential[0] ^= 1
			raw, _ := json.Marshal(bad)
			if e := postcapture.ValidateKey(raw, b.dedupKey); e == nil {
				t.Fatal("credential mismatch accepted")
			}
			if e := postcapture.ValidateKey(proposal.Capture, domain.Hash{42}); e == nil {
				t.Fatal("wrong key accepted")
			}
			for _, field := range []string{"input", "dedup", "display", "observation", "body_sha256", "token_validation", "policy_versions"} {
				var fields map[string]json.RawMessage
				json.Unmarshal(proposal.Capture, &fields)
				delete(fields, field)
				raw, _ := json.Marshal(fields)
				if e := postcapture.Validate(raw); e == nil {
					t.Fatal("missing field accepted", field)
				}
			}
			var fields map[string]json.RawMessage
			json.Unmarshal(proposal.Capture, &fields)
			fields["raw_form"] = json.RawMessage(`"secret"`)
			raw, _ = json.Marshal(fields)
			if e := postcapture.Validate(raw); e == nil {
				t.Fatal("unknown secret field accepted")
			}
		}
	}
	if checked < 2 || !testedCreate {
		t.Fatal("missing create/reply captures")
	}
}
