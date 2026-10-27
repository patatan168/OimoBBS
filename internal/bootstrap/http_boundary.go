// HTTP入口で曖昧なパスと外部ブラウザの管理要求を拒否する共通検査。
package bootstrap

import (
	"net/http"
	"strings"
)

// canonicalRequestPath は正規化せず、変換済みパス・区切り・dot segmentを拒否する。
// POST先をリダイレクトで別経路へ変えず、認証やフォーム発行より前に呼ぶ。
func canonicalRequestPath(r *http.Request) bool {
	if r.URL == nil || !strings.HasPrefix(r.URL.Path, "/") || r.URL.EscapedPath() != r.URL.Path || strings.ContainsAny(r.URL.Path, "\\\x00") || strings.Contains(r.URL.Path, "//") {
		return false
	}
	for _, segment := range strings.Split(r.URL.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// localAdminBrowser はブラウザが付けた発行元情報を全管理経路で検査する。
// ヘッダのないCLIと直接ナビゲーションは許すが、変更操作のOrigin/CSRF検査は別途必須。
func localAdminBrowser(r *http.Request) bool {
	site, present, err := singleRequestHeader(r.Header, "Sec-Fetch-Site")
	return err == nil && (!present || site == "same-origin" || site == "none")
}
