// DAT安全化の出力一致を確認し、変換器の毎回生成と共有を単体比較する。
package compat

import (
	"strings"
	"testing"
)

func BenchmarkDATEscape(b *testing.B) {
	input := strings.Repeat(`日本語の本文 <tag> & "quoted" `, 40)
	legacy := func(s string) string {
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;").Replace(s)
	}
	expected := legacy(input)
	for _, tc := range []struct {
		name    string
		replace func(string) string
	}{
		{"rebuild", legacy}, {"shared", escape},
	} {
		b.Run(tc.name, func(b *testing.B) {
			if tc.replace(input) != expected {
				b.Fatal("different escaped bytes")
			}
			b.ReportAllocs()
			for b.Loop() {
				_ = tc.replace(input)
			}
		})
	}
}
