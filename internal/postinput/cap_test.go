// キャップ秘密の抽出と、表示mailへ秘密を残さない契約を検査する。
package postinput

import (
	"oimobbs/internal/domain"
	"strings"
	"testing"
)

func TestExtractCap(t *testing.T) {
	id := domain.NewID()
	secret := strings.Repeat("A", 43)
	for _, tt := range []struct {
		mail  string
		valid bool
		rest  string
	}{
		{"sage #cap:" + id.String() + ":" + secret, true, "sage"},
		{"", true, ""}, {"sage", true, "sage"},
		{"#cap:" + id.String() + ":" + secret + " #cap:" + id.String() + ":" + secret, false, ""},
		{"x#cap:" + id.String() + ":" + secret, false, ""},
		{"#CAP:" + id.String() + ":" + secret, false, ""},
		{"#cap:" + id.String() + ":short", false, ""},
		{"sage\n#cap:" + id.String() + ":" + secret, false, ""},
		{strings.Repeat(" ", 256) + "#cap:" + id.String() + ":" + secret, false, ""},
	} {
		mail, got, raw, e := ExtractCap(tt.mail)
		if (e == nil) != tt.valid {
			t.Fatalf("unexpected validation for %q", tt.mail)
		}
		if e == nil && (mail != tt.rest || strings.Contains(tt.mail, "#cap:") && (got == nil || *got != id || raw != secret)) {
			t.Fatal("extraction mismatch")
		}
	}
}
