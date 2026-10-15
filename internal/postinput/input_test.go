// 入力由来の秘密・記号とサーバ生成の公開部品を分離して検査する。
package postinput

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"strings"
	"testing"
)

func TestNormalizeAndSecretBoundary(t *testing.T) {
	key := domain.Hash{1}
	fields := map[string]string{"bbs": "news", "FROM": "名&#35;前#private-trip-secret", "mail": "sage", "subject": "題&#x1f600;", "MESSAGE": "&lt;script&gt;\r\n&#65;", "oimo_request_id": "abcdefghijklmnop", "unknown": "unstored-secret"}
	input, e := Prepare(fields, true, key)
	if e != nil {
		t.Fatal(e)
	}
	if input.Name != "名#前" || input.Trip == "" || input.Body != "&lt;script&gt;\nA" || input.Title != "題😀" {
		t.Fatal(input)
	}
	raw, _ := json.Marshal(input)
	if strings.Contains(string(raw), "private-trip-secret") || strings.Contains(string(raw), "unstored-secret") || strings.Contains(string(raw), "abcdefghijklmnop") {
		t.Fatal("secret retained")
	}
	fields["FROM"] = "&#33;id:on"
	input, e = Prepare(fields, true, key)
	if e != nil || input.Name != "!id:on" || input.Trip != "" {
		t.Fatal("reference activated command", e)
	}
}
func TestUnsupportedAndMalformedInputs(t *testing.T) {
	for _, field := range []struct{ k, v string }{{"mail", "sage #cap:id:secret"}, {"MESSAGE", "!status:"}, {"MESSAGE", " \t\n"}, {"oimo_request_id", "short"}, {"FROM", "name\nline"}} {
		f := map[string]string{"bbs": "news", "subject": "title", "MESSAGE": "body"}
		f[field.k] = field.v
		if _, e := Prepare(f, true, domain.Hash{1}); e == nil {
			t.Fatal("accepted", field.k)
		}
	}
}
