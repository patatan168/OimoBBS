// 空白だけを変えた同文の条件を、既存の正規表現保存型へ変換する。
package bootstrap

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// compactBodyCondition は本文だけに適用する入力補助。空白以外の文字は完全一致とする。
// 空白だけの対象は不正な既存条件へ残して検証器に拒否させ、全投稿一致へ変換しない。
func compactBodyCondition(c denialCondition) denialCondition {
	if c.Field != "body" || c.Operator != "compact_exact" {
		return c
	}
	if !utf8.ValidString(c.Value) || len(c.Value) > 1024 {
		return c
	}
	const whitespace = `[\s\p{Z}\x{0085}\x{000B}]*`
	var pattern strings.Builder
	pattern.WriteString(`\A`)
	pattern.WriteString(whitespace)
	count := 0
	for _, ch := range c.Value {
		if unicode.IsSpace(ch) {
			continue
		}
		pattern.WriteString(regexp.QuoteMeta(string(ch)))
		pattern.WriteString(whitespace)
		count++
		if pattern.Len() > 1020 {
			return c
		}
	}
	if count == 0 {
		return c
	}
	pattern.WriteString(`\z`)
	c.Operator, c.Value = "regexp", pattern.String()
	return c
}
