// 管理資産を表示元HTMLの処理に通し、描画が許可されたテンプレートの資産だけを返す。
package bootstrap

import (
	"context"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"oimobbs/internal/waf"
	"oimobbs/internal/webui"
)

// adminAssetCheckContextKey は内部のHTML検証でページ送り状態を追加発行しないための印。
type adminAssetCheckContextKey struct{}

// adminAssetPageResponse はHTML本文を生成・送信せず、実際のページ処理の認可結果を受け取る。
type adminAssetPageResponse struct {
	http.ResponseWriter
	headers http.Header
	status  int
	name    string
	allowed bool
}

func (w *adminAssetPageResponse) Header() http.Header { return w.headers }
func (w *adminAssetPageResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *adminAssetPageResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return len(body), nil
}
func (w *adminAssetPageResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// serveAdminPageAsset はRefererに依存せず、URLに束縛した元ページを同じハンドラーで検証する。
// GETの本文生成はexecuteAdminTemplateで省略し、認可や対象データの存在検査は省略しない。
func (h *adminHandler) serveAdminPageAsset(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/web/assets/") {
		return false
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return true
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/web/assets/page/"), "/", 2)
	if !strings.HasPrefix(r.URL.Path, "/web/assets/page/") || len(parts) != 2 {
		h.fail(w, r, 404, "NOT_FOUND")
		return true
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	page := string(raw)
	source, parseErr := url.ParseRequestURI(page)
	assetPath := "/web/assets/" + parts[1]
	name := webui.AssetName(assetPath)
	if err != nil || parseErr != nil || len(page) > 8192 || !strings.HasPrefix(page, "/") || strings.HasPrefix(page, "//") || (source != nil && strings.HasPrefix(source.Path, "/web/assets/")) || base64.RawURLEncoding.EncodeToString(raw) != parts[0] || name == "" {
		h.fail(w, r, 404, "NOT_FOUND")
		return true
	}
	request := r.Clone(context.WithValue(r.Context(), adminAssetCheckContextKey{}, true))
	u := *r.URL
	u.Path, u.RawPath, u.RawQuery = source.Path, source.RawPath, source.RawQuery
	request.URL = &u
	request.Method, request.Body = "GET", http.NoBody
	request.Header = r.Header.Clone()
	request.Header.Del("If-None-Match")
	request.Header.Del("If-Modified-Since")
	if !canonicalRequestPath(request) {
		h.fail(w, r, 404, "NOT_FOUND")
		return true
	}
	// 表示元の符号化はWAF検査を免除しない。画像・認証などHTML以外の内部処理も実行しない。
	if wafOperation(request, true, "") != waf.Ordinary {
		h.fail(w, r, 404, "NOT_FOUND")
		return true
	}
	if h.repo.wafSettings().Enabled {
		if reason := waf.Inspect(request); reason != "" {
			h.repo.recordWAF(request, reason)
			h.repo.rejectWAF(w, r)
			return true
		}
	}
	probe := &adminAssetPageResponse{ResponseWriter: w, headers: make(http.Header), name: name}
	if page == "/login" {
		// ログインHTMLの宣言だけを使い、CSRFフォーム・Cookieを再発行しない。
		writeAdminPage(probe, 200, adminPage{Login: true})
	} else {
		h.ServeHTTP(probe, request)
	}
	if probe.status == 0 && probe.allowed {
		probe.status = 200
	}
	if probe.status != 200 {
		if location := probe.headers.Get("Location"); location != "" {
			w.Header().Set("Location", location)
		}
		status := probe.status
		if status == 0 {
			status = 404
		}
		w.WriteHeader(status)
		return true
	}
	if !probe.allowed {
		h.fail(w, r, 404, "NOT_FOUND")
		return true
	}
	u = *r.URL
	u.Path, u.RawPath = assetPath, ""
	request.URL = &u
	request.Method = r.Method
	request.Header = r.Header.Clone()
	// HTMLと同じno-storeで配信し、条件付き応答にも先に認可を適用する。
	webui.ServeAdminAsset(w, request)
	return true
}

// renderAdminAssetOnly は呼び出し元がHTMLと同じ認可を済ませた後、表示データを作らず資産宣言だけを検査する。
func renderAdminAssetOnly(w http.ResponseWriter, r *http.Request, t *template.Template, data any) bool {
	if r.Context().Value(adminAssetCheckContextKey{}) != true {
		return false
	}
	if err := executeAdminTemplate(w, w, t, data); err != nil {
		http.Error(w, "画面を表示できません。", 500)
	}
	return true
}
