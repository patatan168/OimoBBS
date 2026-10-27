// CAP専用フラグの省略互換性と保存JSONの厳密な境界を検証する。
package postinput

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"strings"
	"testing"
)

func TestCapOnlyJSONCompatibility(t *testing.T) {
	input, err := Prepare(map[string]string{"subject": "題", "MESSAGE": "本文"}, true, domain.Hash{3})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{input, buildContext().Policy} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		legacy := string(raw)
		if strings.Contains(legacy, `"cap_only"`) {
			t.Fatal("changed normal record format")
		}
		cases := []struct {
			raw               string
			valid, restricted bool
		}{
			{legacy, true, false},
			{strings.Replace(legacy, "{", `{"cap_only":true,`, 1), true, true},
			{strings.Replace(legacy, "{", `{"cap_only":false,`, 1), true, false},
			{strings.Replace(legacy, "{", `{"cap_only":null,`, 1), false, false},
			{strings.Replace(legacy, "{", `{"cap_only":"true",`, 1), false, false},
			{strings.Replace(legacy, "{", `{"cap_only":true,"cap_only":false,`, 1), false, false},
			{strings.Replace(legacy, "{", `{"unknown":true,`, 1), false, false},
			{`{"cap_only":true}`, false, false},
		}
		for _, tc := range cases {
			var restricted bool
			var err error
			switch value.(type) {
			case Input:
				var decoded Input
				err = strictjson.Decode([]byte(tc.raw), &decoded)
				restricted = decoded.CapOnly
			case domain.Policy:
				var decoded domain.Policy
				err = strictjson.Decode([]byte(tc.raw), &decoded)
				restricted = decoded.CapOnly
			}
			if (err == nil) != tc.valid || err == nil && restricted != tc.restricted {
				t.Fatal("JSON contract", tc.raw, err)
			}
		}
	}
}
