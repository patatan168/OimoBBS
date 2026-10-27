// DATの安全化、日時、一覧、従来投稿結果を固定プロファイルで出力する。
package compat

import (
	"fmt"
	"html"
	"oimobbs/internal/domain"
	"oimobbs/internal/textcodec"
	"strings"
	"time"
)

// DateText はJSTの固定投稿日を生成する。
func DateText(t time.Time) string {
	t = t.In(domain.JST)
	return t.Format("2006/01/02") + "(" + []string{"日", "月", "火", "水", "木", "金", "土"}[t.Weekday()] + ") " + t.Format("15:04:05.000")
}

var datEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")

var datNameBoundaries = strings.NewReplacer("</b>", "", "<b>", "")

func escape(s string) string { return datEscaper.Replace(s) }

// PlainDATName は専ブラ用の太字境界を除き、画面で通常の文字列として表示する名前を返す。
// 利用者が入力したエスケープ済みのタグは文字列のまま保持する。返り値はHTMLとして扱わない。
func PlainDATName(raw string) string {
	return html.UnescapeString(datNameBoundaries.Replace(raw))
}

// DAT は利用者入力を安全化してから変換不能文字を数値参照にする。
func DAT(p domain.Post, title string) ([]byte, error) {
	return renderDAT(p, title, false)
}

// LegacyDAT は保存済みdat-v1のキャップ併記を復旧検証用に再現する。
func LegacyDAT(p domain.Post, title string) ([]byte, error) { return renderDAT(p, title, true) }

// renderDAT は保存時の表示契約を選び、名前・本文を安全化して固定DATへ変換する。
func renderDAT(p domain.Post, title string, legacy bool) ([]byte, error) {
	name := escape(p.Name)
	if p.Identity.Trip != "" && (legacy || p.Identity.Cap == "") {
		name += " ◆" + escape(p.Identity.Trip)
	}
	if p.Identity.Cap != "" {
		if legacy {
			name += " " + escape(p.Identity.Cap) + " ★"
		} else {
			name = escape(p.Identity.Cap) + " ★"
		}
	}
	if p.Identity.Slip != "" {
		slip := p.Identity.Slip
		if p.Identity.PublicIP != "" && strings.HasSuffix(slip, ")") {
			slip = strings.TrimSuffix(slip, ")") + " [" + p.Identity.PublicIP + "])"
		}
		// 固定の太字境界で専ブラが名前とSLIPを分離できる。部品自体は必ずescapeする。
		name += " </b>" + escape(slip) + "<b>"
	}
	if p.Identity.PublicIP != "" && p.Identity.Slip == "" {
		name += " [" + escape(p.Identity.PublicIP) + "]"
	}
	date := escape(p.Identity.DateText)
	if p.Identity.ID != "" {
		date += " ID:" + escape(p.Identity.ID+p.Identity.Suffix)
	} else if p.Identity.Suffix != "" {
		date += " " + escape(p.Identity.Suffix)
	}
	body := strings.ReplaceAll(escape(p.Body), "\n", "<br>")
	if p.Number != 1 {
		title = ""
	}
	line := name + "<>" + escape(p.Mail) + "<>" + date + "<>" + body + "<>" + escape(title) + "\n"
	if strings.ContainsAny(strings.TrimSuffix(line, "\n"), "\x00\r\n") {
		return nil, ErrForm
	}
	return textcodec.Encode(line, true)
}

type SubjectEntry struct {
	Key   uint64
	Title string
	Count uint32
}

// Subject は上位層で確定した順位の一覧をSJISで生成する。
func Subject(rows []SubjectEntry) ([]byte, error) {
	var s strings.Builder
	for _, r := range rows {
		title, e := Normalize(r.Title, false, false)
		if e != nil {
			return nil, e
		}
		fmt.Fprintf(&s, "%d.dat<>%s (%d)\n", r.Key, escape(title), r.Count)
	}
	return textcodec.Encode(s.String(), true)
}

// PostResult はlegacy-text-v1の成功・確認・拒否を区別する。
// confirm時のマーカーは専ブラの確認再送パーサに対応し、案内の改行はbrで保持する。
func PostResult(kind, message, link string, notices ...string) ([]byte, error) {
	heading := "ERROR: " + message
	marker := ""
	switch kind {
	case "posted", "already":
		heading = "書きこみが終わりました。"
	case "confirm":
		heading = "書き込み確認"
		marker = "<!-- 2ch_X:cookie -->"
	}
	s := `<!doctype html><html lang="ja"><head><meta charset="Shift_JIS"><title>` + html.EscapeString(heading) + `</title></head><body>` + marker + `<h1>` + html.EscapeString(heading) + `</h1><p>` + html.EscapeString(message) + `</p>`
	for _, notice := range notices {
		notice = strings.ReplaceAll(strings.ReplaceAll(notice, "\r\n", "\n"), "\r", "\n")
		s += `<p>` + strings.ReplaceAll(html.EscapeString(notice), "\n", "<br>\n") + `</p>`
	}
	if link != "" {
		s += `<a href="` + html.EscapeString(link) + `">レスを開く</a>`
	}
	s += `</body></html>`
	return textcodec.Encode(s, true)
}
