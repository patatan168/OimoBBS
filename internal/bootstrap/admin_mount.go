package bootstrap

import (
	"html/template"
	"io"
	"net/http"
	"oimobbs/internal/webui"
	"strings"
)

// adminMountResponse は管理用の相対リダイレクトと描画先だけに隠しパスを適用する。
// ZIPやJSONなどの本文は変換せず、そのまま送信する。
type adminMountResponse struct {
	http.ResponseWriter
	base string
	menu map[string]bool
}

// Unwrap はdeadline・flushを実接続へ渡す。
func (w *adminMountResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WriteHeader は管理リダイレクトを帯域予約前に隠しパスへ揃える。
func (w *adminMountResponse) WriteHeader(status int) {
	if location := w.Header().Get("Location"); strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
		w.Header().Set("Location", w.base+location)
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *adminMountResponse) Write(body []byte) (int, error) { return w.ResponseWriter.Write(body) }

// executeAdminTemplate はwriterのマウント情報を辿り、管理画面のリンクとフォームを描画する。
func executeAdminTemplate(w http.ResponseWriter, destination io.Writer, original *template.Template, data any) error {
	base := ""
	var menu map[string]bool
	for current := w; current != nil; {
		if guarded, ok := current.(*evidenceQueryWriter); ok {
			current = guarded.ResponseWriter
			continue
		}
		if mounted, ok := current.(*adminMountResponse); ok {
			if mounted.base != "" {
				base = mounted.base
			}
			if menu == nil {
				menu = mounted.menu
			}
		}
		next, ok := current.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		current = next.Unwrap()
	}
	t, err := webui.AdminTemplate(strings.TrimSuffix(original.Name(), ".html"), base).Clone()
	if err != nil {
		return err
	}
	t.Funcs(template.FuncMap{
		"adminCan": func(path string) bool { return menu[path] },
		"adminHome": func() string {
			for _, path := range []string{"/", "/boards", "/auto-reports"} {
				if menu[path] {
					return base + path
				}
			}
			return base + "/login"
		},
	})
	return t.Execute(destination, data)
}

// WriteHeaderChecked は帯域待ち後の権限・期限検査を下流writerへ渡す。
func (w *adminMountResponse) WriteHeaderChecked(status int, check func() error) error {
	if location := w.Header().Get("Location"); strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
		w.Header().Set("Location", w.base+location)
	}
	if checked, ok := w.ResponseWriter.(interface{ WriteHeaderChecked(int, func() error) error }); ok {
		return checked.WriteHeaderChecked(status, check)
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	w.ResponseWriter.WriteHeader(status)
	return nil
}

// WriteChecked は証拠本文を変換せず、送信予約後の失効検査も省かずに渡す。
func (w *adminMountResponse) WriteChecked(body []byte, check func() error) (int, error) {
	if checked, ok := w.ResponseWriter.(interface {
		WriteChecked([]byte, func() error) (int, error)
	}); ok {
		return checked.WriteChecked(body, check)
	}
	if check != nil {
		if err := check(); err != nil {
			return 0, err
		}
	}
	return w.ResponseWriter.Write(body)
}
