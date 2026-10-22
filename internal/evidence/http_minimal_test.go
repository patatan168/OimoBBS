// 現行原本に固定・重複項目を保存せず、旧項目と旧スキーマを読み替えないことを検査する。
package evidence

import (
	"encoding/json"
	"testing"
)

func TestHTTPObservationRejectsRemovedOriginalFields(t *testing.T) {
	raw, err := json.Marshal(decodedObservationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for key, oldValue := range map[string]string{
		"declared_charset": `null`, "clock_status": `"unknown"`,
		"clock_source": `"unconfigured"`, "clock_offset_ms": `null`, "clock_observed_at_ns": `null`,
	} {
		if _, exists := fields[key]; exists {
			t.Fatal("removed original field still stored", key)
		}
		fields[key] = json.RawMessage(oldValue)
		old, _ := json.Marshal(fields)
		if ValidateHTTPObservation(old) == nil {
			t.Fatal("removed field accepted", key)
		}
		delete(fields, key)
	}
	var gaps []MissingField
	if err = json.Unmarshal(fields["missing_fields"], &gaps); err != nil {
		t.Fatal(err)
	}
	for _, gap := range gaps {
		if gap.Field == "declared_charset" || gap.Field == "clock_offset_ms" || gap.Field == "clock_observed_at_ns" {
			t.Fatal("obsolete missing reason", gap)
		}
	}
	for _, schema := range []string{"http-observation-v2", "http-observation-v3"} {
		fields["schema"], _ = json.Marshal(schema)
		old, _ := json.Marshal(fields)
		if ValidateHTTPObservation(old) == nil {
			t.Fatal("old schema accepted", schema)
		}
	}
}
