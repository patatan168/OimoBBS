// Package webui は依存ライブラリのないHTML・CSS・JavaScriptを配信する。
package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"oimobbs/internal/compat"
	"strings"
	"sync"
)

//go:embed templates/*.html assets/*.css assets/*.js inline/*.js inline/*.css
var files embed.FS

var assetCompression = compat.NewCompressionCache(256<<10, 1)
var versionedAssetPaths = make(map[string]string)
var assetNames = make(map[string]string)
var publicAssets = loadPublicAssets()

// loadPublicAssets は起動時に固定CSS/JSだけを読み、内容に束縛した表現を準備する。
func loadPublicAssets() map[string]compat.Representation {
	entries, err := files.ReadDir("assets")
	if err != nil {
		panic(err)
	}
	result := make(map[string]compat.Representation, len(entries)*2)
	for _, entry := range entries {
		kind := "text/javascript; charset=utf-8"
		if strings.HasSuffix(entry.Name(), ".css") {
			kind = "text/css; charset=utf-8"
		} else if !strings.HasSuffix(entry.Name(), ".js") {
			continue
		}
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		body, err := files.ReadFile("assets/" + name)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(body)
		tag := fmt.Sprintf("asset-%x", sum)
		p := compat.Representation{DAT: body, ContentType: kind, DisableRange: true, ETagIdentity: `"` + tag + `-identity"`, ETagGzip: `"` + tag + compat.GzipETagSuffix + `"`, ETagZstd: `"` + tag + compat.ZstdETagSuffix + `"`, Compress: assetCompression.Compress}
		versioned := fmt.Sprintf("/web/assets/%x/%s", sum, name)
		result["/web/assets/"+name], result[versioned] = p, p
		versionedAssetPaths[name] = versioned
		assetNames["/web/assets/"+name], assetNames[versioned] = name, name
	}
	return result
}

// Template は独立したHTMLと共通部品を読み込む。構文不正は起動時に検出する。
func Template(name string) *template.Template {
	return template.Must(template.New(name+".html").Funcs(templateFunctions).Funcs(template.FuncMap{"assetPath": assetPath, "adminRecoveryHead": func() template.HTML { return adminRecovery.head }, "adminCan": func(string) bool { return false }, "adminCurrent": func(string) bool { return false }, "adminHome": func() string { return "/login" }, "adminBase": func() string { return "" }, "adminURL": func(path string) string { return path }}).ParseFS(files, "templates/common.html", "templates/"+name+".html"))
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

// AssetName は既知の完全一致URLだけを資産名へ変換する。
func AssetName(path string) string { return assetNames[path] }

// AdminAssetPath は表示元ページに束縛した管理資産URLを返す。
func AdminAssetPath(name, base, page string) (string, error) {
	path, err := assetPath(name)
	if err != nil {
		return "", err
	}
	return base + "/web/assets/page/" + base64.RawURLEncoding.EncodeToString([]byte(page)) + strings.TrimPrefix(path, "/web/assets"), nil
}

// PublicAsset は一般閲覧画面で使用する既知の資産だけを許可する。
func PublicAsset(path string) bool {
	switch assetNames[path] {
	case "ui.css", "ui.js", "public.css", "list.css", "list.js", "thread.css", "thread.js", "dates.css", "dates.js":
		return true
	}
	return false
}

// ServePublicAsset は公開画面の資産を配信し、管理専用の資産は404にする。
func ServePublicAsset(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/web/assets/") {
		return false
	}
	if !PublicAsset(r.URL.Path) {
		http.NotFound(w, r)
		return true
	}
	return ServeAsset(w, r)
}

// authenticatedAssetResponse は共有キャッシュを禁止し、HTMLと同じ保存禁止を適用する。
type authenticatedAssetResponse struct{ http.ResponseWriter }

func (w authenticatedAssetResponse) WriteHeader(status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.ResponseWriter.WriteHeader(status)
}
func (w authenticatedAssetResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ServeAdminAsset は表示元の管理HTMLと同じ認可を確認済みの呼び出し元に限り使用する。
func ServeAdminAsset(w http.ResponseWriter, r *http.Request) bool {
	return ServeAsset(authenticatedAssetResponse{w}, r)
}

// ServeAsset は既知の資産を返す。呼び出し元が公開範囲と認証を確認する。
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
