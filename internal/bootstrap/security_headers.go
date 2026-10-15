// TLS応答のHTTPS固定と、不要なブラウザ機能の拒否を共通化する。
package bootstrap

import "net/http"

// securityTransportHeaders は拒否・過負荷を含む全応答へ適用する。HTTPにはHSTSを付けない。
func securityTransportHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
