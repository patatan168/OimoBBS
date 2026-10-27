// 公開・管理の既存Host条件と宣言サイズを、頻度枠の消費より先に照合する。
package bootstrap

import (
	"net/http"
	"net/url"
	"oimobbs/internal/waf"
)

const wafAdminBodyLimit = waf.MaxRequestBodyBytes

// wafIngressHandler はWAF有効時だけ、設定済みの接続先と入口の本文上限を先に確認する。
// Hostは既存ルーターと同じ正規化規則を使い、転送ヘッダーから補正しない。
func (r *Repository) wafIngressHandler(next http.Handler, origin *url.URL, maxBody int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.wafSettings().Enabled && (!wafHostMatches(req.Host, origin) || req.ContentLength < -1 || req.ContentLength > maxBody) {
			reason := "body_size"
			if !wafHostMatches(req.Host, origin) {
				reason = "host"
			}
			r.recordWAF(req, reason)
			r.rejectWAF(w, req)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// wafHostMatches は通常の設定済みHostを確保なしで比較し、省略された標準portだけ従来規則へ戻す。
func wafHostMatches(host string, origin *url.URL) bool {
	if origin == nil || host == "" {
		return false
	}
	if host == origin.Host {
		return true
	}
	parsed, err := parseOrigin(origin.Scheme + "://" + host)
	return err == nil && normalizedOrigin(parsed) == normalizedOrigin(origin)
}

// rejectWAF は本文・規則名を保存せず拒否する。HTTP/1の未受信本文を待たず接続を終了する。
// HTTP/2では同じ接続の別streamを巻き込まず、標準サーバーのstream終了処理へ委ねる。
func (r *Repository) rejectWAF(w http.ResponseWriter, req *http.Request) {
	r.wafBlocked.Add(1)
	w.Header().Set("Cache-Control", "no-store")
	if req.ProtoMajor == 1 && (req.ContentLength != 0 || len(req.TransferEncoding) != 0) {
		w.Header().Set("Connection", "close")
	}
	http.Error(w, "この要求は許可されていません。", http.StatusForbidden)
}
