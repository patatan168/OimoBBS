// 専ブラの投稿確認で案内の改行・空行を保ち、入力をHTMLとして実行させない。
package compat

import (
	"oimobbs/internal/textcodec"
	"strings"
	"testing"
)

func TestPostResultNoticeLineBreaks(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n", "\r"} {
		t.Run(strings.ReplaceAll(strings.ReplaceAll(newline, "\r", "CR"), "\n", "LF"), func(t *testing.T) {
			raw, err := PostResult("confirm", "同意して再送してください。", "", "Cookieの説明"+newline+"次の行", "【利用規約】"+newline+newline+"規約の本文 <script>alert(1)</script>"+newline+"最後の行")
			if err != nil {
				t.Fatal(err)
			}
			got, err := textcodec.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"<!-- 2ch_X:cookie -->", "<p>Cookieの説明<br>\n次の行</p>", "<p>【利用規約】<br>\n<br>\n規約の本文 &lt;script&gt;alert(1)&lt;/script&gt;<br>\n最後の行</p>"} {
				if !strings.Contains(got, want) {
					t.Fatal("notice line break or escaping lost", got)
				}
			}
			if strings.Contains(got, "<script>") || strings.Contains(got, "\r") {
				t.Fatal("unsafe or unnormalized notice", got)
			}
		})
	}
}
