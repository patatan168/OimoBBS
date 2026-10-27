// 管理マニュアルを認証済み専用経路で配信する。
package bootstrap

import (
	"bytes"
	"net/http"
	"oimobbs/internal/webui"
)

var adminManualTemplate = webui.Template("manual")

// manual は表示を先に検証し、失敗時に成功ヘッダを送らない。
func (h *adminHandler) manual(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var body bytes.Buffer
	if err := executeAdminTemplate(w, &body, adminManualTemplate, nil); err != nil {
		h.fail(w, r, 500, "TEMPLATE_FAILED")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(200)
	_, _ = w.Write(body.Bytes())
}
