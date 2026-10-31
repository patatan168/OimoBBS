// 投稿後の表示を含むスレッドHTMLを元テンプレートとbyte単位で照合する。
package bootstrap

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"strings"
	"testing"
)

func checkThreadRendering(t testing.TB, view threadPage) {
	t.Helper()
	var expected bytes.Buffer
	if err := threadTemplate.Execute(&expected, view); err != nil {
		t.Fatal(err)
	}
	got, err := renderThreadPage(view)
	if err != nil || !bytes.Equal(got, expected.Bytes()) {
		t.Fatalf("HTML differs: %v\ngot: %s\nwant: %s", err, got, expected.Bytes())
	}
}

func TestThreadRenderingEquivalent(t *testing.T) {
	if fastThreadTemplate == nil {
		t.Fatal("現在のテンプレートを高速化できない")
	}
	for _, text := range []string{"plain", "日本語😀", `<script>alert("x")</script>`, "a+b&c'\"<>\x00", "bad\xff\xfe\n\r\t"} {
		for _, reply := range []bool{false, true} {
			for _, mail := range []string{"", text} {
				view := threadPage{Title: text, Board: "probe", Key: "123", Count: 5, CanReply: reply, CapOnly: true, MoveTarget: "javascript:alert(1)", Previous: "/prev?a=1&b=2", Next: "/next?a=1&b=2"}
				for i := range 5 {
					view.Rows = append(view.Rows, threadRow{Number: i + 1, Name: text, Mail: mail, Date: text, Body: text})
				}
				checkThreadRendering(t, view)
			}
		}
	}
	for _, board := range []string{"", "a/b", "a&b", "a b", "日本語", "<script>"} {
		checkThreadRendering(t, threadPage{Board: board, Key: "1", Rows: []threadRow{{Number: 1, Body: "本文"}}})
	}
	checkThreadRendering(t, threadPage{Board: "probe", Key: "1"})
}

// 描画文脈や式が変わったテンプレートを、HTML本文用の命令へ誤って変換しない。
func TestThreadRendererRejectsChangedContexts(t *testing.T) {
	for _, source := range []string{
		`<a href="{{.Body}}">link</a>`,
		`<span data-x="{{.Body}}">text</span>`,
		`<script>{{.Body}}</script>`,
		`{{if .Name}}{{.Body}}{{end}}`,
		`{{printf "%s" .Body}}`,
	} {
		parsed := template.Must(template.New("changed").Parse(source))
		if err := parsed.Execute(io.Discard, threadRow{Name: "name", Body: "body"}); err != nil {
			t.Fatal(err)
		}
		if _, ok := compileThreadRow(parsed.Tree.Root); ok {
			t.Fatal("未対応の文脈を高速描画した", source)
		}
	}
}

func FuzzThreadRenderingEquivalent(f *testing.F) {
	f.Add("name", "mail", "date", "本文 <&> +", int32(1))
	f.Fuzz(func(t *testing.T, name, mail, date, body string, n int32) {
		if len(name)+len(mail)+len(date)+len(body) > 16384 {
			return
		}
		checkThreadRendering(t, threadPage{Title: name, Board: "probe", Key: "123", Count: 3, CanReply: true, Rows: []threadRow{{Number: int(n), Name: name, Mail: mail, Date: date, Body: body}}})
	})
}

func BenchmarkThreadPageRendering(b *testing.B) {
	view := threadPage{Title: "スレッド", Board: "probe", Key: "123", Count: 1000, CanReply: true}
	for i := range 50 {
		view.Rows = append(view.Rows, threadRow{Number: 951 + i, Name: "名前", Date: "2026/11/01 ID:abc", Body: strings.Repeat("本文 >>1 https://example.invalid/ ", 10)})
	}
	checkThreadRendering(b, view)
	for _, fast := range []bool{false, true} {
		b.Run(fmt.Sprint("fast=", fast), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if fast {
					if _, err := renderThreadPage(view); err != nil {
						b.Fatal(err)
					}
				} else {
					var buf bytes.Buffer
					if err := threadTemplate.Execute(&buf, view); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
