// WebのGET/HEADに圧縮形式の受け入れを要求し、本文を作る前に拒否する。
package compat

import (
	"net/http"
	"strings"
)

// RequireCompressedRead はgzip/zstdを受け入れないGET/HEADを空本文の406で拒否する。
// 構文不正は400。拒否済みならfalseを返す。専ブラ等の例外判定は呼出元が行う。
// 応答本文の圧縮を強制せず、他のmethodと要求ヘッダーは変更しない。
func RequireCompressedRead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	w.Header().Add("Vary", "Accept-Encoding")
	accepted, err := acceptsCompressedRead(strings.Join(r.Header.Values("Accept-Encoding"), ","))
	if err == nil && accepted {
		return true
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", "0")
	for _, name := range []string{"Content-Type", "Content-Encoding", "ETag", "Last-Modified"} {
		h.Del(name)
	}
	status := http.StatusNotAcceptable
	if err != nil {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	return false
}

// acceptsCompressedRead は既存のq値構文と重複値規則で、利用可能な圧縮形式を確認する。
// ヘッダー省略も、このWeb専用方針では受け入れの宣言不足として扱う。
func acceptsCompressedRead(header string) (bool, error) {
	switch header {
	case "", "identity":
		return false, nil
	case "gzip", "zstd":
		return true, nil
	}
	qualities, err := encodingQualities(header)
	if err != nil {
		return false, err
	}
	for _, coding := range []string{"gzip", "zstd"} {
		q, ok := qualities[coding]
		if !ok {
			q = qualities["*"]
		}
		if q > 0 {
			return true, nil
		}
	}
	return false, nil
}
