// 板一覧と編集画面。入力を保持し、動作範囲を管理者へ表示する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postinput"
	"oimobbs/internal/webui"
	"slices"
	"strings"
)

type adminBoardsPage struct {
	CountryCodes          []string
	Rows                  []AdminBoard
	Next                  string
	Editing               bool
	CanCreate             bool
	CreateReady           bool
	Name, Action, Message string
	ThreadAction          string
	ModerationAction      string
	PublicURL, BoardKey   string
	Values                url.Values
}

var adminBoardsTemplate = webui.Template("boards")

// CapThreadURL はCAP専用を選択済みの公開作成フォームへのリンクを返す。資格情報は含めない。
func (p adminBoardsPage) CapThreadURL(key string) string {
	return p.PublicURL + "/web/post?" + url.Values{"bbs": {key}, "oimo_cap_only": {"1"}}.Encode()
}

func writeAdminBoards(w http.ResponseWriter, status int, page adminBoardsPage) {
	var buf bytes.Buffer
	if e := executeAdminTemplate(w, &buf, adminBoardsTemplate, page); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// SlipModes は管理画面が指定できる表示方式を返す。
func (p adminBoardsPage) SlipModes() []string {
	return []string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"}
}

// DisplayCommandAllowed は旧一括設定も反映して個別チェックの初期状態を返す。
func (p adminBoardsPage) DisplayCommandAllowed(command string) bool {
	if p.Values.Get("allow_thread_strengthen") != "true" {
		return false
	}
	var names *[]string
	if json.Unmarshal([]byte(p.Values.Get("display_commands")), &names) != nil {
		return false
	}
	return names == nil || slices.Contains(*names, command)
}

// ExtendModes は継承指定を含むスレッド全体の回線表示を返す。
func (p adminBoardsPage) ExtendModes() []string { return append([]string{"default"}, p.SlipModes()...) }

// DisplayCommandAvailable は編集中の板既定で受理できる命令だけを表示する。
// 許可状態とは別に判定し、非表示にした項目の保存値は保持する。
func (p adminBoardsPage) DisplayCommandAvailable(command string) bool {
	mode := p.Values.Get("slip_mode")
	if p.Values.Get("require_public_ip") == "true" {
		if mode == "vvvvv" || mode == "vvvvvv" {
			mode = "vvvvvv"
		} else {
			mode = "vvvv"
		}
	}
	return postinput.DisplayCommandCompatible(domain.Policy{IDMode: p.Values.Get("id_mode"), SlipMode: mode}, command)
}

// ExtendModeAvailable はID継承の命令を受理できる回線表示グループだけを表示する。
func (p adminBoardsPage) ExtendModeAvailable(mode string) bool {
	return p.DisplayCommandAvailable("!extend:default:" + mode + "::")
}

// ReadingAction は編集中の板の閲覧制限画面への経路を返す。
func (p adminBoardsPage) ReadingAction() string {
	return strings.TrimSuffix(p.Action, "/settings") + "/reading"
}
