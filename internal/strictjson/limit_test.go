// 保存経路の明示上限を拡張しても、通常Decodeと厳密性が変わらないことを検証する。
package strictjson

import (
	"bytes"
	"testing"
)

func TestExplicitStoredLimit(t *testing.T) {
	raw := append([]byte(`{"value":"`), bytes.Repeat([]byte("a"), MaxBytes)...)
	raw = append(raw, []byte(`"}`)...)
	var v struct {
		Value string `json:"value"`
	}
	if Decode(raw, &v) == nil || Validate(raw) == nil {
		t.Fatal("通常上限を緩和した")
	}
	if err := DecodeLimit(raw, &v, 2<<20); err != nil || len(v.Value) != MaxBytes {
		t.Fatal(err)
	}
	if err := ValidateLimit(raw, 2<<20); err != nil {
		t.Fatal(err)
	}
	bad := append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"value":"duplicate"}`)...)
	if DecodeLimit(bad, &v, 2<<20) == nil || ValidateLimit(bad, 2<<20) == nil {
		t.Fatal("拡張上限で重複を受理した")
	}
	if DecodeLimit(raw, &v, 8<<20+1) == nil {
		t.Fatal("明示上限の最大値を超えた")
	}
}
