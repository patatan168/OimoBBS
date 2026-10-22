// 終了レスの通常文字列はテンプレートでエスケープして表示する。
package bootstrap

import (
	"bytes"
	"net/http"
	"net/url"
	"oimobbs/internal/webui"
)

type threadSettingsPage struct {
	Action, Message string
	Values          url.Values
}

var threadSettingsTemplate = webui.Template("thread-settings")

// writeThreadSettings は入力をエスケープしてから管理画面の応答を書き出す。
func writeThreadSettings(w http.ResponseWriter, status int, page threadSettingsPage) {
	var b bytes.Buffer
	if e := executeAdminTemplate(w, &b, threadSettingsTemplate, page); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
