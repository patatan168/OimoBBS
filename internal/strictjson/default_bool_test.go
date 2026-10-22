// bool補完の従来map方式と、直接補完の受理条件・値・サイズ上限を比較する。
package strictjson

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type defaultDocument struct {
	Flag    bool   `json:"flag"`
	Payload string `json:"payload"`
}

func referenceDefaultBool(raw []byte, dst any, name string, value bool) error {
	if err := Validate(raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if _, ok := fields[name]; !ok {
		fields[name] = json.RawMessage(strconv.FormatBool(value))
	}
	normalized, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	return referenceDecode(normalized, dst)
}

func checkDefaultBool(t testing.TB, raw []byte, value bool) {
	t.Helper()
	var old, got defaultDocument
	oe, ge := referenceDefaultBool(raw, &old, "flag", value), DecodeDefaultBool(raw, &got, "flag", value)
	if (oe == nil) != (ge == nil) || oe == nil && !reflect.DeepEqual(old, got) {
		t.Fatalf("default changed: old=%v new=%v", oe, ge)
	}
}

func FuzzDecodeDefaultBoolEquivalence(f *testing.F) {
	for _, raw := range []string{`{}`, `{"payload":"本文"}`, `{"flag":true,"payload":""}`, `{"flag":null,"payload":""}`, `{"flag":false,"\u0066lag":true,"payload":"x"}`, `{"payload":"\ud800"}`, ` { "payload" : "<&>\u2028" } `, `{"Flag":true,"payload":"x"}`} {
		f.Add([]byte(raw), false)
	}
	f.Fuzz(func(t *testing.T, raw []byte, value bool) { checkDefaultBool(t, raw, value) })
}

func TestDecodeDefaultBoolSizeAndInputOwnership(t *testing.T) {
	for _, length := range []int{1, MaxBytes/6 - 64, MaxBytes / 6, MaxBytes/6 + 64, MaxBytes - 32, MaxBytes - 16, MaxBytes} {
		for _, char := range []string{"x", "<"} {
			raw := []byte(`{"payload":"` + strings.Repeat(char, length) + `"}`)
			original := string(raw)
			for _, value := range []bool{false, true} {
				checkDefaultBool(t, raw, value)
			}
			if string(raw) != original {
				t.Fatal("input changed")
			}
		}
	}
}
