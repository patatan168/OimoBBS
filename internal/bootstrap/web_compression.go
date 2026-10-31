// 専ブラの互換URLを圧縮受け入れ必須化の対象から除く。
package bootstrap

// legacyUncompressedPath は正規URL確認後の専ブラ用menu・投稿CGI・feed・DAT経路を識別する。
// UA・query・RangeだけではWeb経路を例外にしない。
func legacyUncompressedPath(path string) bool {
	switch path {
	case "/bbsmenu.html", "/bbsmenu.json", "/test/bbs.cgi":
		return true
	default:
		return legacyFeedPath(path)
	}
}
