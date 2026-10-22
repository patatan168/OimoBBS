// 認証記録が秘密・接続元を漏らさず、任意の文字列と大量記録を拒否することを検査する。
package securityaudit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestAuthRedactionAndAggregation(t *testing.T) {
	var out bytes.Buffer
	l, err := New(&out)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 105; i++ {
		l.Record("login", "failed", "192.0.2.1:secret-cookie", "", now)
	}
	l.Record("password-secret", "failed", "192.0.2.1", "", now)
	l.Record("login", "failed", "192.0.2.1", "", now.Add(time.Minute))
	if strings.Contains(out.String(), "192.0.2.1") || strings.Contains(out.String(), "secret") || !strings.Contains(out.String(), `"suppressed":5`) || strings.Count(out.String(), `"msg":"security_auth"`) != 101 {
		t.Fatal("redaction or bounded recording")
	}
}
