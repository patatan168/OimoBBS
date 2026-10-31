// webassets はHTMLテンプレートと静的資産を事前縮小し、決定的な配信用ファイルを生成する。
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
	"oimobbs/internal/zstdencode"
)

type assetSize struct {
	SourceSHA256 string `json:"source_sha256"`
	Source       int    `json:"source"`
	Minified     int    `json:"minified"`
	Gzip         int    `json:"gzip,omitempty"`
	Zstd         int    `json:"zstd,omitempty"`
}

func main() {
	root := flag.String("root", ".", "リポジトリのルート")
	check := flag.Bool("check", false, "生成物を書き換えず一致を検証する")
	flag.Parse()
	if err := run(*root, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newMinifier はテンプレート構文とHTMLの構造・属性・空白を保つ縮小器を作る。
func newMinifier() *minify.M {
	m := minify.New()
	m.Add("text/html", &html.Minifier{KeepDefaultAttrVals: true, KeepDocumentTags: true, KeepEndTags: true, KeepQuotes: true, KeepWhitespace: true, TemplateDelims: html.GoTemplateDelims})
	m.AddFunc("text/css", css.Minify)
	m.AddFunc("text/javascript", js.Minify)
	return m
}

// generate は全入力の検証と圧縮が成功するまでファイルを書き換えない。
func generate(source string) (map[string][]byte, error) {
	m := newMinifier()
	output := make(map[string][]byte)
	sizes := make(map[string]assetSize)
	var encoder zstdencode.Encoder
	for _, directory := range []string{"assets", "inline", "templates"} {
		entries, err := os.ReadDir(filepath.Join(source, directory))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				return nil, fmt.Errorf("unexpected source directory: %s", entry.Name())
			}
			name := directory + "/" + entry.Name()
			raw, err := os.ReadFile(filepath.Join(source, name))
			if err != nil {
				return nil, err
			}
			body, err := minifySource(m, name, raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			output[name] = body
			size := assetSize{SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), Source: len(raw), Minified: len(body)}
			if directory == "assets" {
				compressed, err := gzipBody(body)
				if err != nil {
					return nil, err
				}
				output[name+".gz"] = compressed
				output[name+".zst"] = encoder.Encode(body)
				size.Gzip, size.Zstd = len(compressed), len(output[name+".zst"])
			}
			sizes[name] = size
		}
	}
	manifest, err := json.MarshalIndent(sizes, "", "  ")
	if err != nil {
		return nil, err
	}
	output["manifest.json"] = append(manifest, '\n')
	return output, nil
}

// minifySource はSVGを原文のまま保持し、対応する構文だけを縮小する。
func minifySource(m *minify.M, name string, raw []byte) ([]byte, error) {
	kind := map[string]string{".html": "text/html", ".css": "text/css", ".js": "text/javascript"}[filepath.Ext(name)]
	if kind == "" {
		if strings.HasSuffix(name, ".svg") {
			return raw, nil
		}
		return nil, fmt.Errorf("unsupported asset extension: %s", name)
	}
	return m.Bytes(kind, raw)
}

// gzipBody は時刻やファイル名を含めず最高圧縮のgzipを生成する。
func gzipBody(body []byte) ([]byte, error) {
	var result bytes.Buffer
	w, err := gzip.NewWriterLevel(&result, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(body); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

// run は生成物の内容とファイル集合を照合し、生成時だけ古い生成物を除去する。
func run(root string, check bool) error {
	source := filepath.Join(root, "internal", "webui")
	output, err := generate(source)
	if err != nil {
		return err
	}
	target := filepath.Join(source, "generated")
	var names []string
	for name := range output {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(target, name)
		current, err := os.ReadFile(path)
		if err == nil && bytes.Equal(current, output[name]) {
			continue
		}
		if check {
			return fmt.Errorf("stale generated asset: %s; run go generate ./internal/webui", name)
		}
		if err := writeAsset(path, output[name]); err != nil {
			return err
		}
	}
	err = filepath.WalkDir(target, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		name, err := filepath.Rel(target, path)
		if err != nil {
			return err
		}
		if _, ok := output[filepath.ToSlash(name)]; ok {
			return nil
		}
		if check {
			return fmt.Errorf("unexpected generated asset: %s", name)
		}
		return os.Remove(path)
	})
	if err != nil {
		return err
	}
	fmt.Printf("webassets: %d generated files verified\n", len(output))
	return nil
}

// writeAsset は同じディレクトリの一時ファイルを置換し、途中までの本文を残さない。
func writeAsset(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".asset-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
