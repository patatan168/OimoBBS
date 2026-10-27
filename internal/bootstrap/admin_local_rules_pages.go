// ローカルルールの通常文字列はテンプレートでエスケープして表示する。
package bootstrap

import (
	"bytes"
	"net/http"
	"net/url"
	"oimobbs/internal/webui"
)

type localRulesPage struct {
	Action, Message string
	Values          url.Values
}

var localRulesTemplate = webui.Template("local-rules")

// writeLocalRules は入力をエスケープしてから管理画面の応答を書き出す。
func writeLocalRules(w http.ResponseWriter, status int, page localRulesPage) {
	var b bytes.Buffer
	if e := executeAdminTemplate(w, &b, localRulesTemplate, page); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
