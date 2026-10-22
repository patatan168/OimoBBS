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
	base   string
	menu   map[string]bool
	page   string
	status int
}

// Unwrap はdeadline・flushを実接続へ渡す。
func (w *adminMountResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WriteHeader は管理リダイレクトを帯域予約前に隠しパスへ揃える。
func (w *adminMountResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	if location := w.Header().Get("Location"); strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
		w.Header().Set("Location", w.base+location)
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *adminMountResponse) Write(body []byte) (int, error) { return w.ResponseWriter.Write(body) }

// executeAdminTemplate はwriterのマウント情報を辿り、管理画面のリンクとフォームを描画する。
func executeAdminTemplate(w http.ResponseWriter, destination io.Writer, original *template.Template, data any) error {
	base := ""
	page := ""
	status := 0
	var asset *adminAssetPageResponse
	var menu map[string]bool
	for current := w; current != nil; {
		if guarded, ok := current.(*adminCheckedWriter); ok {
			current = guarded.ResponseWriter
			continue
		}
		if probe, ok := current.(*adminAssetPageResponse); ok {
			asset = probe
		}
		if mounted, ok := current.(*adminMountResponse); ok {
			if page == "" {
				page = mounted.page
			}
			if status == 0 {
				status = mounted.status
			}
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
	if login, ok := data.(adminPage); ok && login.Login {
		page, menu = "/login", nil
	}
	// 通常のエラー表示はログイン用の共通資産だけを使う。入力エラーの専用画面は元ページの認可を維持する。
	if page == "" || status >= 400 && original.Name() == "admin.html" {
		page = "/login"
	}
	referenced := false
	t.Funcs(template.FuncMap{
		"assetPath": func(name string) (string, error) {
			if asset != nil && asset.name == name {
				referenced = true
			}
			return webui.AdminAssetPath(name, base, page)
		},
		"adminCan": func(path string) bool { return menu[path] },
		"adminCurrent": func(path string) bool {
			current, _, _ := strings.Cut(page, "?")
			return current == path || path != "/" && strings.HasPrefix(current, path+"/")
		},
		"adminHome": func() string {
			for _, path := range []string{"/", "/boards", "/auto-reports"} {
				if menu[path] {
					return base + path
				}
			}
			return base + "/login"
		},
	})
	if asset != nil {
		err := t.ExecuteTemplate(io.Discard, "admin-assets", data)
		asset.allowed = err == nil && referenced
		return err
	}
	return t.Execute(destination, data)
}

// WriteHeaderChecked は帯域待ち後の権限・期限検査を下流writerへ渡す。
func (w *adminMountResponse) WriteHeaderChecked(status int, check func() error) error {
	if location := w.Header().Get("Location"); strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
		w.Header().Set("Location", w.base+location)
	}
	if checked, ok := w.ResponseWriter.(interface{ WriteHeaderChecked(int, func() error) error }); ok {
		if err := checked.WriteHeaderChecked(status, check); err != nil {
			return err
		}
		if w.status == 0 {
			w.status = status
		}
		return nil
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	w.ResponseWriter.WriteHeader(status)
	if w.status == 0 {
		w.status = status
	}
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
