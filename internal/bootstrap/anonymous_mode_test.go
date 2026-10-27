// 全投稿Cookie必須の完全保存形式と旧形式拒否を検査する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"testing"
)

func TestAnonymousPolicyCurrentSchemaOnly(t *testing.T) {
	p := AnonymousPolicy{Schema: "anon-policy-v4", Mode: "required", Enabled: 1, Generation: 1, KeyID: 4, ReplyRule: domain.NewID(), CreateRule: domain.NewID(), Modes: []anonymousModeBoundary{}}
	raw, _ := json.Marshal(p)
	if _, err := decodeAnonymous(raw); err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{"anon-policy-v1", "anon-policy-v2", "anon-policy-v3"} {
		bad := p
		bad.Schema = schema
		raw, _ := json.Marshal(bad)
		if _, err := decodeAnonymous(raw); err == nil {
			t.Fatal("old schema accepted", schema)
		}
	}
	for _, mode := range []string{"off", "optional"} {
		bad := p
		bad.Mode = mode
		raw, _ := json.Marshal(bad)
		if _, err := decodeAnonymous(raw); err == nil {
			t.Fatal("non-required mode accepted", mode)
		}
	}
	next := p
	next.Generation++
	if err := validateAnonymousTransition(p, next); err != nil {
		t.Fatal(err)
	}
	next.Enabled++
	if err := validateAnonymousTransition(p, next); err == nil {
		t.Fatal("activation changed")
	}
	var fields map[string]json.RawMessage
	raw, _ = json.Marshal(p)
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "mode_history")
	raw, _ = json.Marshal(fields)
	if _, err := decodeAnonymous(raw); err == nil {
		t.Fatal("incomplete policy accepted")
	}
}
