// Package webui は依存ライブラリのないHTML・CSS・JavaScriptを配信する。
package webui

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"oimobbs/internal/compat"
	"strings"
	"sync"
)

//go:embed templates/*.html assets/*.css assets/*.js
var files embed.FS

var assetCompression = compat.NewCompressionCache(256<<10, 1)
var versionedAssetPaths = make(map[string]string, 3)
var publicAssets = loadPublicAssets()

// loadPublicAssets は起動時に固定CSS/JSだけを読み、内容に束縛した表現を準備する。
func loadPublicAssets() map[string]compat.Representation {
	result := make(map[string]compat.Representation, 6)
	for _, asset := range []struct{ path, name, kind string }{
		{"/web/assets/ui.css", "assets/ui.css", "text/css; charset=utf-8"},
		{"/web/assets/ui.js", "assets/ui.js", "text/javascript; charset=utf-8"},
		{"/web/assets/admin.js", "assets/admin.js", "text/javascript; charset=utf-8"},
	} {
		body, err := files.ReadFile(asset.name)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(body)
		tag := fmt.Sprintf("asset-%x", sum)
		p := compat.Representation{DAT: body, ContentType: asset.kind, DisableRange: true, ETagIdentity: `"` + tag + `-identity"`, ETagGzip: `"` + tag + compat.GzipETagSuffix + `"`, ETagZstd: `"` + tag + compat.ZstdETagSuffix + `"`, Compress: assetCompression.Compress}
		versioned := fmt.Sprintf("/web/assets/%x/%s", sum, strings.TrimPrefix(asset.name, "assets/"))
		result[asset.path], result[versioned] = p, p
		versionedAssetPaths[strings.TrimPrefix(asset.name, "assets/")] = versioned
	}
	return result
}

// Template は独立したHTMLと共通部品を読み込む。構文不正は起動時に検出する。
func Template(name string) *template.Template {
	return template.Must(template.New(name+".html").Funcs(templateFunctions).Funcs(template.FuncMap{"assetPath": assetPath, "adminCan": func(string) bool { return false }, "adminHome": func() string { return "/login" }, "adminBase": func() string { return "" }, "adminURL": func(path string) string { return path }}).ParseFS(files, "templates/"+name+".html", "templates/common.html"))
}

// assetPath は内容に束縛した既知資産のURLを返す。未知名はテンプレート生成時に拒否する。
func assetPath(name string) (string, error) {
	path, ok := versionedAssetPaths[name]
	if !ok {
		return "", fmt.Errorf("unknown asset %q", name)
	}
	return path, nil
}

// immutableAssetResponse は成功した版付き資産だけを長期キャッシュへ変更する。
// 圧縮失敗などの503はServeDATのno-cacheを維持し、障害応答を固定しない。
type immutableAssetResponse struct{ http.ResponseWriter }

// WriteHeader は成功時だけ内容固定のcache方針を適用し、下位の帯域予約へ渡す。
func (w immutableAssetResponse) WriteHeader(status int) {
	if status == http.StatusOK || status == http.StatusNotModified {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.ResponseWriter.WriteHeader(status)
}

// Unwrap はsocketのdeadlineや送信制御を下位writerへ渡す。
func (w immutableAssetResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ServeAsset は既知の公開資産だけを返す。Host等の検証後、認証前に呼ぶ。
// /web/assets/以外ならfalse。テンプレートやディレクトリの列挙は公開しない。
func ServeAsset(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/web/assets/") {
		return false
	}
	representation, ok := publicAssets[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return true
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", 405)
		return true
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if strings.Count(strings.TrimPrefix(r.URL.Path, "/web/assets/"), "/") == 1 {
		w = immutableAssetResponse{w}
	}
	compat.ServeDAT(w, r, representation)
	return true
}

var adminTemplates sync.Map

// AdminTemplate は設定済みのパスに束縛した管理テンプレートを生成し、並列描画で共有する。
// 外部URL・公開側の絶対URL・ページ内アンカーは変更しない。
func AdminTemplate(name, base string) *template.Template {
	key := name + "\x00" + base
	if cached, ok := adminTemplates.Load(key); ok {
		return cached.(*template.Template)
	}
	t := Template(name).Funcs(template.FuncMap{
		"adminBase": func() string { return base },
		"adminURL": func(path string) string {
			if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") {
				return base + path
			}
			return path
		},
		"assetPath": func(name string) (string, error) { p, err := assetPath(name); return base + p, err },
	})
	actual, _ := adminTemplates.LoadOrStore(key, t)
	return actual.(*template.Template)
}
