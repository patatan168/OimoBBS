// WebのHTTP世代制限と、専ブラ互換URLの例外範囲を公開入口間で共有する。
package compat

import (
	"net/http"
	"oimobbs/internal/delivery"
	"strings"
)

// LegacyClientPath は正規パスの専ブラ用menu・投稿CGI・feed・DATを識別する。
// 正規URLの検査と、管理マウント配下の除外は呼出元で行う。
func LegacyClientPath(path string) bool {
	switch path {
	case "/bbsmenu.html", "/bbsmenu.json", "/test/bbs.cgi":
		return true
	default:
		return LegacyFeedPath(path)
	}
}

// LegacyFeedPath は専ブラの板別一覧・設定・ローカルルール・DATのパス形状を返す。
func LegacyFeedPath(path string) bool {
	p := strings.Split(path, "/")
	if len(p) == 3 {
		return p[2] == "subject.txt" || p[2] == "SETTING.TXT" || p[2] == "head.txt"
	}
	return len(p) == 4 && p[2] == "dat" && strings.HasSuffix(p[3], ".dat")
}

// RequireModernHTTP はHTTP/2・HTTP/3以外を空本文の505で拒否する。全メソッドが対象。
// 専ブラとSSHトンネルの例外は呼出元で選び、拒否時は要求本文を読まない。
func RequireModernHTTP(w http.ResponseWriter, r *http.Request) bool {
	if r.ProtoMajor == 2 || r.ProtoMajor == 3 {
		return true
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", "0")
	for _, name := range []string{"Content-Type", "Content-Encoding", "ETag", "Last-Modified"} {
		h.Del(name)
	}
	delivery.RejectUnreadBody(w, r)
	w.WriteHeader(http.StatusHTTPVersionNotSupported)
	return false
}
