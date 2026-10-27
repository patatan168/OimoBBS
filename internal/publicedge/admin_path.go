// 管理ルートの明示設定を検査し、公開APIと投稿経路の制限を維持する。
package publicedge

// validAdminPath は保存サーバーと同じ1区画のマウント形式を受け入れる。空なら管理転送なし。
func validAdminPath(path string) bool {
	if path == "" || path == "/admin" {
		return true
	}
	if len(path) < 17 || len(path) > 129 || path[0] != '/' {
		return false
	}
	for _, ch := range path[1:] {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}
