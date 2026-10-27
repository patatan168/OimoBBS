// ローカルルールの構造化・検査・安全な公開HTMLの生成を担当する。
package bootstrap

import (
	"bytes"
	"html/template"
	"net/url"
	"oimobbs/internal/compat"
	"oimobbs/internal/store"
	"oimobbs/internal/textcodec"
	"strings"
)

// validateLocalRules は未知形式・過大入力・危険なリンクを保存前と復旧時に拒否する。
func validateLocalRules(rules []ruleParagraph) error {
	if rules == nil || len(rules) > 128 {
		return store.ErrCorrupt
	}
	total := 0
	for _, rule := range rules {
		total += len(rule.Text)
		normalized, err := compat.Normalize(rule.Text, false, false)
		if err != nil || normalized != rule.Text || strings.TrimSpace(rule.Text) == "" || len(rule.Text) > 2048 || total > 16<<10 {
			return store.ErrCorrupt
		}
		switch rule.Kind {
		case "paragraph", "item":
		case "link":
			u, err := url.Parse(rule.Text)
			if err != nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" || u.Scheme != "http" && u.Scheme != "https" {
				return store.ErrCorrupt
			}
		default:
			return store.ErrCorrupt
		}
	}
	return nil
}

// parseLocalRulesText は空行を除き、箇条書きと独立したURLを通常の段落から分ける。
func parseLocalRulesText(text string) ([]ruleParagraph, error) {
	if len(text) > 32<<10 {
		return nil, store.ErrCorrupt
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	rules := []ruleParagraph{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rule := ruleParagraph{Kind: "paragraph", Text: line}
		if strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "- ") {
			rule.Kind, rule.Text = "item", strings.TrimSpace(line[2:])
		} else if strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "http://") {
			rule.Kind = "link"
		}
		rules = append(rules, rule)
	}
	return rules, validateLocalRules(rules)
}

// localRulesText は設定をHTMLを含まない一行単位の編集テキストへ戻す。
func localRulesText(rules []ruleParagraph) string {
	lines := make([]string, 0, len(rules))
	for _, rule := range rules {
		text := rule.Text
		if rule.Kind == "item" {
			text = "* " + text
		}
		lines = append(lines, text)
	}
	return strings.Join(lines, "\n")
}

var localRulesHeadTemplate = template.Must(template.New("local-rules").Parse(`{{range .}}{{if eq .Kind "item"}}<ul><li>{{.Text}}</li></ul>{{else if eq .Kind "link"}}<p><a href="{{.Text}}" rel="nofollow noopener">{{.Text}}</a></p>{{else}}<p>{{.Text}}</p>{{end}}
{{end}}`))

// localRulesHead は専ブラ用のShift_JIS HTML断片を作り、本文をエスケープする。
func localRulesHead(rules []ruleParagraph) ([]byte, error) {
	if err := validateLocalRules(rules); err != nil {
		return nil, err
	}
	var body bytes.Buffer
	if err := localRulesHeadTemplate.Execute(&body, rules); err != nil {
		return nil, err
	}
	return textcodec.Encode(body.String(), true)
}
