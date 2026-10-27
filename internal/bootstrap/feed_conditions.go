// 一覧のSHA-256を短く表記し、既存の長い検証子でも全文の再送を避ける。
package bootstrap

import (
	"net/http"
)

// publicDataHeaders はDAT・一覧・設定・JSONに不要なscript/style許可を外し、短い拒否方針を返す。
// HTML画面の資産許可、nosniff、Referrer-Policyは変更しない。
func publicDataHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
}
