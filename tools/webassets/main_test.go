// 生成物の再現性、テンプレートの動作、圧縮の復元と古い成果物の検出を検証する。
package main

import (
	"bytes"
	"compress/gzip"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/testutil"
)

func TestMinifyPreservesTemplateAndPreformattedText(t *testing.T) {
	source := []byte(`<!-- removable -->
<!DOCTYPE html><html><head><title>{{.Title}}</title></head><body>
<input type="checkbox"{{if .Selected}} checked{{end}} value="{{.Value}}">
<p><span>A</span> <span>B</span></p><pre>  AA
    AA  </pre><textarea>{{.Value}}</textarea></body></html>`)
	minified, err := minifySource(newMinifier(), "templates/test.html", source)
	if err != nil {
		t.Fatal(err)
	}
	if len(minified) >= len(source) || bytes.Contains(minified, []byte("removable")) {
		t.Fatal("HTML not minified")
	}
	for _, selected := range []bool{true, false} {
		data := struct {
			Title, Value string
			Selected     bool
		}{`<script>alert(1)</script>`, "\"<&\n  投稿", selected}
		var output bytes.Buffer
		tmpl, err := template.New("fixture").Parse(string(minified))
		if err != nil {
			t.Fatal(err)
		}
		if err := tmpl.Execute(&output, data); err != nil {
			t.Fatal(err)
		}
		body := output.String()
		for _, want := range []string{"<pre>  AA\n    AA  </pre>", "<span>A</span> <span>B</span>", "&lt;script&gt;alert(1)&lt;/script&gt;", "<textarea>&#34;&lt;&amp;\n  投稿</textarea>"} {
			if !bytes.Contains(output.Bytes(), []byte(want)) {
				t.Fatalf("lost %q: %s", want, body)
			}
		}
		if bytes.Contains(output.Bytes(), []byte(" checked")) != selected {
			t.Fatal("conditional attribute changed", body)
		}
	}
}

func TestGeneratedAssetsAreDeterministicAndDetectStaleFiles(t *testing.T) {
	root := t.TempDir()
	webui := filepath.Join(root, "internal", "webui")
	for name, body := range map[string]string{
		"assets/test.js":      "// comment\nconst value = /a+b/.test('aab');\nconsole.log(value);",
		"assets/test.css":     "/* comment */ body { color: #ffffff; margin: 0px; }",
		"assets/icon.svg":     `<svg xmlns="http://www.w3.org/2000/svg"/>`,
		"inline/test.js":      "// comment\nconsole.log('inline');",
		"templates/test.html": "<!-- comment -->\n<p>{{.}}</p>",
	} {
		if err := writeAsset(filepath.Join(webui, name), []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err != nil {
		t.Fatal(err)
	}
	first, err := generate(webui)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generate(webui)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range first {
		if !bytes.Equal(body, second[name]) {
			t.Fatal("non-deterministic output", name)
		}
		if filepath.Ext(name) != ".js" && filepath.Ext(name) != ".css" && filepath.Ext(name) != ".svg" {
			continue
		}
		if !bytes.HasPrefix([]byte(name), []byte("assets/")) {
			continue
		}
		g, err := gzip.NewReader(bytes.NewReader(first[name+".gz"]))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(g)
		g.Close()
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatal("gzip mismatch", name, err)
		}
		decoded, err = testutil.DecodeZstd(first[name+".zst"])
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatal("zstd mismatch", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(webui, "assets", "test.js"), []byte("console.log('changed');"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err == nil {
		t.Fatal("stale output accepted")
	}
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(webui, "generated", "assets", "removed.js")
	if err := os.WriteFile(stale, []byte("stale"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err == nil {
		t.Fatal("extra output accepted")
	}
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale asset retained", err)
	}
	previous, err := os.ReadFile(filepath.Join(webui, "generated", "assets", "test.js"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webui, "assets", "test.js"), []byte("function broken( {"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := run(root, false); err == nil {
		t.Fatal("invalid JavaScript accepted")
	}
	retained, err := os.ReadFile(filepath.Join(webui, "generated", "assets", "test.js"))
	if err != nil || !bytes.Equal(previous, retained) {
		t.Fatal("invalid source changed generated output", err)
	}
}
