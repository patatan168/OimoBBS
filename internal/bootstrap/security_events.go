// WAF・投稿検出・全板規制を、管理専用の7日間ログへ接続する。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/securitylog"
	"os"
	"path/filepath"
	"time"
)

// recordWAF は本文・query・認証ヘッダーを読まず、安全なパスの抜粋と規則分類だけを記録する。
func (r *Repository) recordWAF(req *http.Request, reason string) {
	if r.securityLog == nil {
		return
	}
	path := req.URL.EscapedPath()
	// 管理パスはnonceや登録用URLを含み得るため、入口名だけを残す。
	_, base, _ := r.cfg.adminEndpoint()
	if base != "" && len(path) >= len(base) && path[:len(base)] == base {
		path = base + "/（管理要求）"
	}
	r.securityLog.Add(securitylog.Event{At: time.Now(), Source: "waf", Reason: reason, Rejected: true, Path: path})
}

func (g *abuseGuard) recordSecurity(e guardEntry, source, reason string, rejected bool) {
	if g.log == nil {
		return
	}
	event := securitylog.Event{Operation: e.id.String(), At: time.Unix(0, int64(e.at)), Source: source, Reason: reason, Rejected: rejected, Board: e.board.String(), Thread: e.thread, Post: e.number, Body: e.body}
	if e.match != nil {
		event.MatchOperation = e.match.id.String()
		event.MatchBody = e.match.signature.sample
		event.MatchBoard = e.match.board.String()
		event.MatchThread = e.match.thread
		event.MatchPost = e.match.number
	}
	g.log.Add(event)
}

// appendSecurityLogRoot は旧データにも存在し得る任意の管理ログ領域だけを追加許可する。
func appendSecurityLogRoot(root string, names []string) []string {
	info, err := os.Lstat(filepath.Join(root, "security-events"))
	if err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return append(names, "security-events")
	}
	return names
}
