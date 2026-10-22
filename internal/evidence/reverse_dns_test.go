// DNS観測の保存検証と旧形式の拒否を確認する。
package evidence

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"testing"
)

func TestReverseDNSObservationValidationAndOldSchemaRejection(t *testing.T) {
	base := decodedObservationFixture(t)
	valid := ReverseDNSObservation{Names: []string{"dns.example"}, ConfirmedName: "dns.example", Status: "confirmed", ObservedAt: domain.Time(1800000000000000000), Resolver: "system"}
	for _, tc := range []struct {
		name   string
		change func(*ReverseDNSObservation)
		ok     bool
	}{
		{"confirmed", func(*ReverseDNSObservation) {}, true},
		{"mismatch retains PTR", func(v *ReverseDNSObservation) { v.ConfirmedName = ""; v.Status = "mismatch" }, true},
		{"forward unchecked retains PTR", func(v *ReverseDNSObservation) { v.ConfirmedName = ""; v.Status = "unchecked" }, true},
		{"absent", func(v *ReverseDNSObservation) { v.ConfirmedName = ""; v.Status = "absent"; v.Names = []string{} }, true},
		{"unknown mode", func(v *ReverseDNSObservation) { v.Resolver = "header" }, false},
		{"invalid name", func(v *ReverseDNSObservation) { v.Names = []string{"bad\n.example"} }, false},
		{"missing observation time", func(v *ReverseDNSObservation) { v.ObservedAt = 0 }, false},
		{"inconsistent confirmation", func(v *ReverseDNSObservation) { v.Status = "mismatch" }, false},
		{"different confirmed name", func(v *ReverseDNSObservation) { v.ConfirmedName = "other.example" }, false},
		{"absent with names", func(v *ReverseDNSObservation) { v.Status = "absent"; v.ConfirmedName = "" }, false},
		{"null names", func(v *ReverseDNSObservation) { v.Names = nil }, false},
		{"duplicate names", func(v *ReverseDNSObservation) { v.Names = []string{"dns.example", "dns.example"} }, false},
		{"unsorted names", func(v *ReverseDNSObservation) { v.Names = []string{"z.example", "dns.example"} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := valid
			tc.change(&value)
			v, err := base.WithReverseDNS(value)
			if (err == nil) != tc.ok {
				t.Fatalf("acceptance: %v", err)
			}
			if err == nil {
				raw, _ := json.Marshal(v)
				if ValidateHTTPObservation(raw) != nil {
					t.Fatal("saved DNS rejected")
				}
			}
		})
	}
	v, err := base.WithReverseDNS(valid)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(v)
	oldSchema := bytes.Replace(raw, []byte("http-observation-v4"), []byte("http-observation-v1"), 1)
	if ValidateHTTPObservation(oldSchema) == nil {
		t.Fatal("old observation schema accepted")
	}
	if _, err := PostingHTTPObservation(oldSchema); err == nil {
		t.Fatal("old observation treated as an unrelated capture")
	}
	oldForm, _ := json.Marshal(map[string]any{"schema": "form-post-v5", "observation": v})
	if _, err := PostingHTTPObservation(oldForm); err == nil {
		t.Fatal("old form treated as an unrelated capture")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "reverse_dns")
	old, _ := json.Marshal(fields)
	if ValidateHTTPObservation(old) == nil {
		t.Fatal("missing new field accepted")
	}
}
