// 認証済み管理画面へ、保存領域を使わない架空ログのダウンロードを提供する。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/disclosure"
	"strconv"
)

// evidenceSample は実ログの権限や再認証を要求せず、共通の管理認証内で見本だけを返す。
func (h *adminHandler) evidenceSample(w http.ResponseWriter, r *http.Request) {
	raw, e := disclosure.SampleZIP()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="evidence-sample.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}
