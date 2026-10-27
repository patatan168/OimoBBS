// 管理画面の認証復帰に必要な固定コードだけを、内容ハッシュで許可してHTMLへ埋め込む。
package webui

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"strings"
)

type adminRecoveryContent struct {
	head          template.HTML
	script, style string
}

var adminRecovery = loadAdminRecovery()

// loadAdminRecovery は利用者の値を含まない埋込みファイルと、そのCSPハッシュを準備する。
func loadAdminRecovery() adminRecoveryContent {
	read := func(name string) string {
		raw, err := files.ReadFile("inline/admin-recovery." + name)
		if err != nil {
			panic(err)
		}
		return string(raw)
	}
	script, style := read("js"), read("css")
	hash := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	return adminRecoveryContent{
		head:   template.HTML("<style>" + style + "</style><script>" + script + "</script>"),
		script: hash(script), style: hash(style),
	}
}

// AdminRecoveryPolicy は復帰処理の固定内容だけを許可し、unsafe-inlineを導入しない。
func AdminRecoveryPolicy(policy string) string {
	policy = strings.Replace(policy, "script-src 'self'", "script-src 'self' "+adminRecovery.script, 1)
	return strings.Replace(policy, "style-src 'self'", "style-src 'self' "+adminRecovery.style, 1)
}
