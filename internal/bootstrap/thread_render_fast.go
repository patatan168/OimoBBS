// 標準HTMLテンプレートが決めたレス部分だけを型付きで描画し、反射と同じ値の再変換を省く。
package bootstrap

import (
	"bytes"
	"html/template"
	"io"
	"oimobbs/internal/webui"
	"strconv"
	"strings"
	"text/template/parse"
)

type threadRowInstruction struct {
	text         string
	field        int
	mail, noMail []threadRowInstruction
}

var fastThreadTemplate, threadRowInstructions = compileThreadRenderer()

// threadRange は外側のRows反復一つだけを選ぶ。別構造への変更は標準描画へ戻す。
func threadRange(t *template.Template) (int, *parse.RangeNode) {
	index := -1
	var found *parse.RangeNode
	for i, node := range t.Tree.Root.Nodes {
		if row, ok := node.(*parse.RangeNode); ok {
			if found != nil || row.Pipe.String() != ".Rows" || row.ElseList != nil {
				return -1, nil
			}
			index, found = i, row
		}
	}
	return index, found
}

// compileThreadRenderer は自動escape後の既知のfield/文脈だけを採用する。
// HTMLの定数は元テンプレートから借り、未対応の変更では全体を標準Executeへ戻す。
func compileThreadRenderer() (*template.Template, []threadRowInstruction) {
	canonical := webui.Template("thread")
	if err := canonical.Execute(io.Discard, threadPage{}); err != nil {
		return nil, nil
	}
	_, row := threadRange(canonical)
	if row == nil {
		return nil, nil
	}
	program, ok := compileThreadRow(row.List)
	if !ok {
		return nil, nil
	}
	fast := webui.Template("thread")
	index, row := threadRange(fast)
	if row == nil {
		return nil, nil
	}
	slot := template.Must(template.New("rows").Parse("{{.RenderedRows}}"))
	fast.Tree.Root.Nodes[index] = slot.Tree.Root.Nodes[0]
	return fast, program
}

// compileThreadRow はレス本文内の定数・既知field・Mailの有無だけを型付き命令へ変える。
func compileThreadRow(list *parse.ListNode) ([]threadRowInstruction, bool) {
	if list == nil {
		return nil, true
	}
	var result []threadRowInstruction
	for _, node := range list.Nodes {
		instruction := threadRowInstruction{field: -1}
		switch n := node.(type) {
		case *parse.TextNode:
			instruction.text = string(n.Text)
		case *parse.ActionNode:
			field, ok := threadRowField(n.Pipe)
			if !ok {
				return nil, false
			}
			instruction.field = field
		case *parse.IfNode:
			if n.Pipe.String() != ".Mail" {
				return nil, false
			}
			var ok bool
			instruction.mail, ok = compileThreadRow(n.List)
			if !ok {
				return nil, false
			}
			instruction.noMail, ok = compileThreadRow(n.ElseList)
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
		result = append(result, instruction)
	}
	return result, true
}

// threadRowField はHTML文脈に対応する標準escape列も照合し、未対応の式を拒否する。
func threadRowField(pipe *parse.PipeNode) (int, bool) {
	if len(pipe.Decl) != 0 || len(pipe.Cmds) < 2 || len(pipe.Cmds[0].Args) != 1 {
		return 0, false
	}
	field := -1
	switch value := pipe.Cmds[0].Args[0].(type) {
	case *parse.FieldNode:
		if len(value.Ident) != 1 {
			return 0, false
		}
		for i, name := range []string{"Number", "Name", "Mail", "Date", "Body"} {
			if value.Ident[0] == name {
				field = i
			}
		}
	case *parse.VariableNode:
		if len(value.Ident) != 2 || value.Ident[0] != "$" {
			return 0, false
		}
		if value.Ident[1] == "Board" {
			field = 5
		}
		if value.Ident[1] == "Key" {
			field = 6
		}
	}
	if field < 0 {
		return 0, false
	}
	for _, command := range pipe.Cmds[1:] {
		if len(command.Args) != 1 {
			return 0, false
		}
		name, ok := command.Args[0].(*parse.IdentifierNode)
		if !ok {
			return 0, false
		}
		if field >= 1 && field <= 4 {
			if name.Ident != "_html_template_htmlescaper" {
				return 0, false
			}
			continue
		}
		switch name.Ident {
		case "_html_template_htmlescaper", "_html_template_attrescaper", "_html_template_urlescaper", "_html_template_urlnormalizer":
		default:
			return 0, false
		}
	}
	return field, true
}

// plainThreadIdentifier はURLと属性で追加変換の要らない実際の板キー・数値キーだけを許す。
func plainThreadIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range []byte(value) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// threadText は標準html/templateのHTML本文escapeと同じ置換を行う。
func threadText(value string) string {
	return strings.ReplaceAll(template.HTMLEscapeString(value), "+", "&#43;")
}

// appendThreadInstructions は事前escape済みの値だけを元テンプレートの定数へ接続する。
func appendThreadInstructions(out *strings.Builder, program []threadRowInstruction, values *[7]string, hasMail bool) {
	for _, instruction := range program {
		if instruction.field >= 0 {
			out.WriteString(values[instruction.field])
			continue
		}
		out.WriteString(instruction.text)
		if hasMail {
			appendThreadInstructions(out, instruction.mail, values, hasMail)
		} else {
			appendThreadInstructions(out, instruction.noMail, values, hasMail)
		}
	}
}

// renderThreadPage はレスの同じ値を一度だけescapeし、周辺部分は標準テンプレートで描く。
// 未対応のテンプレートやURL入力では標準描画へ戻り、返却HTMLのbyteと公開条件を保つ。
func renderThreadPage(view threadPage) ([]byte, error) {
	chosen := threadTemplate
	if fastThreadTemplate != nil && plainThreadIdentifier(view.Board) && plainThreadIdentifier(view.Key) {
		var rows strings.Builder
		rows.Grow(len(view.Rows) * 256)
		for _, row := range view.Rows {
			values := [7]string{strconv.Itoa(row.Number), threadText(row.Name), threadText(row.Mail), threadText(row.Date), threadText(row.Body), view.Board, view.Key}
			appendThreadInstructions(&rows, threadRowInstructions, &values, row.Mail != "")
		}
		view.RenderedRows = template.HTML(rows.String())
		chosen = fastThreadTemplate
	}
	var out bytes.Buffer
	if err := chosen.Execute(&out, view); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
