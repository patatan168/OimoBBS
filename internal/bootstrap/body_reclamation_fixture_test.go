// 回収証明fixtureの各改変を、実署名された正本と同じ検証器へ渡す。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

func checkBodyReclamationFixture(t *testing.T, proof app.BodyReclamation, public ed25519.PublicKey) {
	t.Helper()
	raw, e := os.ReadFile("../../docs/design/fixtures/body-reclamation.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Schema string `json:"schema"`
		Cases  []struct {
			Name   string `json:"name"`
			Change string `json:"change"`
			Valid  bool   `json:"valid"`
		} `json:"cases"`
	}
	if strictjson.Decode(raw, &fixture) != nil || fixture.Schema != "body-reclamation-v1" {
		t.Fatal("fixture schema")
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			raw, _ := json.Marshal(proof)
			var v app.BodyReclamation
			if e := strictjson.Decode(raw, &v); e != nil {
				t.Fatal(e)
			}
			switch tc.Change {
			case "none":
			case "owner":
				v.Owner = domain.NewID()
			case "thread":
				v.Key++
			case "deletion":
				v.Deletion = domain.NewID()
			case "sequence":
				v.Sequence++
			case "time":
				v.At++
			case "floor":
				v.Floor++
			case "records":
				v.RecordsSHA[0] ^= 1
			case "dedup":
				v.DedupSHA[0] ^= 1
			case "rate":
				v.RateSHA[0] ^= 1
			case "policy":
				v.Policy.Version++
			case "bump":
				v.After.BumpValue++
			case "length":
				v.Files[0].Length++
			case "file_hash":
				v.Files[0].SHA[0] ^= 1
			case "path":
				v.Files[0].Name = "../private"
			case "signature":
				v.Signature += "="
			default:
				t.Fatal("unknown fixture change")
			}
			if valid := v.Verify(public) == nil; valid != tc.Valid {
				t.Fatal("validator result", valid)
			}
		})
	}
	raw, _ = json.Marshal(proof)
	if e = validateBodyReclamation("body", raw, raw); e == nil {
		t.Fatal("reclamation proof was mutable")
	}
}
