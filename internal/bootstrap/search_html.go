// 検索結果をエスケープしたHTMLで返し、JavaScriptなしの条件指定とページ移動を提供する。
package bootstrap

import (
	"bytes"
	"net/http"
	"strconv"
)

func writeSearch(w http.ResponseWriter, r *http.Request, page searchView) {
	var body bytes.Buffer
	if e := searchTemplate.Execute(&body, page); e != nil {
		threadError(w, r, 503, "現在検索できません。")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(200)
	if r.Method != "HEAD" {
		_, _ = w.Write(body.Bytes())
	}
}
