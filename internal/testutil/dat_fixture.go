// 合成1000レスを作る検証用fixture。稼働データは参照しない。
package testutil

import (
	"crypto/sha256"
	"fmt"
	"oimobbs/internal/textcodec"
	"strings"
)

// DATFixture は公開DATと同じ文字コードで1000行を作る。稼働データを読まない。
func DATFixture(kind string) []byte {
	var b strings.Builder
	for i := 1; i <= 1000; i++ {
		body := fmt.Sprintf("返信%d >>%d 検証の本文です。 https://example.invalid/%d ", i, max(1, i-1), i%43)
		if kind == "entropy" {
			for j := range 5 {
				body += fmt.Sprintf("%x ", sha256.Sum256([]byte(fmt.Sprintf("%d:%d", i, j))))
			}
		} else if kind == "mixed" {
			switch i % 4 {
			case 0:
				body += fmt.Sprintf("日本語の投稿です。日時や番号が変わっても文章は繰り返します。番号%d ", i)
			case 1:
				body += fmt.Sprintf("A short English reply about network compression and performance. item=%d state=ready ", i)
			case 2:
				body += fmt.Sprintf(`{"item":%d,"enabled":true,"message":"small payload and repeated fields","list":[1,2,3,4]}`, i)
			case 3:
				body += fmt.Sprintf("%x %x", sha256.Sum256([]byte(fmt.Sprint(i))), sha256.Sum256([]byte(fmt.Sprint(i+10000))))
			}
		} else {
			phrases := []string{"新しい投稿を確認しました。", "表示と更新について確認しています。", "夕食の話をしましょう。", "こちらの環境では問題ありません。", "次の返信を待っています。"}
			body += strings.Repeat(phrases[i%len(phrases)], 3)
		}
		fmt.Fprintf(&b, "名前%d<>sage<>2026/10/06(火) 12:%02d:%02d ID:%08d<>%s<>\n", i%17, i/60%60, i%60, i%97, body)
	}
	raw, err := textcodec.Encode(b.String(), true)
	if err != nil {
		panic(err)
	}
	return raw
}
