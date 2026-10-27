// 別のloopbackリスナーで、試験管理キーによる認証後に板を作成する。
package compatprobe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/compat"
	"oimobbs/internal/identity"
	"strconv"
	"strings"
	"time"
)

// ProbeAdmin は試験管理専用ハンドラ。製品の管理者・役割管理とは別の認証。
type ProbeAdmin struct {
	server       *Server
	origin       *url.URL
	passwordHash [32]byte
}

// AdminHandler は公開サーバに登録しない独立した管理ハンドラを生成する。
func (s *Server) AdminHandler(origin, password string) (*ProbeAdmin, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "http" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("admin origin must be a loopback HTTP origin")
	}
	if strings.EqualFold(u.Host, s.base.Host) {
		return nil, errors.New("admin and public origins must be separate")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if (e != nil || !ip.IsLoopback()) && u.Hostname() != "localhost" {
		return nil, errors.New("admin origin must be loopback")
	}
	if len(password) != 64 {
		return nil, errors.New("admin key must be 32 bytes in hexadecimal")
	}
	if _, e = hex.DecodeString(password); e != nil {
		return nil, e
	}
	return &ProbeAdmin{server: s, origin: u, passwordHash: sha256.Sum256([]byte(password))}, nil
}

var adminPage = template.Must(template.New("admin").Parse(`<!doctype html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>試験サーバ管理</title></head><body><h1>試験サーバ管理</h1><p>{{.Notice}}</p>{{if .Message}}<p role="alert">{{.Message}}</p>{{end}}
{{if .LoggedIn}}<h2>板を追加する</h2><form method="post" action="/boards"><input type="hidden" name="csrf" value="{{.CSRF}}"><p><label>板キー <input name="key" value="{{.Key}}" pattern="[a-z][a-z0-9_]{0,31}" maxlength="32" required></label></p><p><label>板名 <input name="name" value="{{.Name}}" maxlength="128" required></label></p><button type="submit">板を追加</button></form><h2>登録済みの板</h2><ul>{{range .Boards}}<li><a href="{{.URL}}">{{.Name}}</a></li>{{end}}</ul><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">ログアウト</button></form>
{{else}}<p>起動時に案内された管理キーファイルの内容を入力してください。</p><form method="post" action="/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><p><label>管理キー <input type="password" name="password" autocomplete="current-password" required></label></p><button type="submit">ログイン</button></form>{{end}}</body></html>`))

type adminView struct {
	Notice, Message, CSRF, Key, Name string
	LoggedIn                         bool
	Boards                           []menuBoard
}

func (a *ProbeAdmin) session(r *http.Request) bool {
	c, e := r.Cookie("oimo_probe_admin")
	if e != nil {
		return false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 || len(parts[1]) != 64 {
		return false
	}
	sec, e := strconv.ParseInt(parts[0], 10, 64)
	now := a.server.clock().Unix()
	if e != nil || sec > now || sec <= now-8*3600 {
		return false
	}
	mac := identity.MAC(a.passwordHash[:], "oimo/probe-admin-session/v1", []byte(parts[0]), []byte(parts[1]))
	return hmac.Equal([]byte(parts[2]), []byte(mac.String()))
}
func (a *ProbeAdmin) show(w http.ResponseWriter, r *http.Request, status int, message, key, name string) {
	view := adminView{Notice: notice, Message: message, Key: key, Name: name, LoggedIn: a.session(r), CSRF: formCSRF(w, r, a.passwordHash[:], "oimo_probe_admin_csrf", "admin", false, a.server.clock())}
	if view.LoggedIn {
		view.Boards = a.server.menuBoards()
	}
	renderHTML(w, r, status, adminPage, view)
}

// ServeHTTP は管理経路のHost、接続元、認証、CSRF、Originを検査する。
func (a *ProbeAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	ip, pe := netip.ParseAddr(host)
	if e != nil || pe != nil || !ip.IsLoopback() || !strings.EqualFold(r.Host, a.origin.Host) || badPath(r.URL) {
		http.Error(w, "invalid admin boundary", 400)
		return
	}
	if r.URL.Path == "/" {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(405)
			return
		}
		a.show(w, r, 200, "", "", "")
		return
	}
	if r.URL.Path != "/login" && r.URL.Path != "/boards" && r.URL.Path != "/logout" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(405)
		return
	}
	if r.URL.Path != "/login" && !a.session(r) {
		http.Error(w, "管理者ログインが必要です。", 401)
		return
	}
	if !sameOrigin(r, a.origin) {
		http.Error(w, "origin denied", 403)
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil {
		http.Error(w, "body too large", 413)
		return
	}
	f, e := compat.ParseForm(b, r.Header.Get("Content-Type"), true)
	if e != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	if !csrfValid(r, f["csrf"], a.passwordHash[:], "oimo_probe_admin_csrf", "admin", a.server.clock()) {
		http.Error(w, "invalid CSRF", 403)
		return
	}
	a.action(w, r, f)
}
func (a *ProbeAdmin) action(w http.ResponseWriter, r *http.Request, f map[string]string) {
	switch r.URL.Path {
	case "/login":
		got := sha256.Sum256([]byte(f["password"]))
		if !hmac.Equal(got[:], a.passwordHash[:]) {
			a.show(w, r, 401, "管理キーを確認してください。", "", "")
			return
		}
		issued := strconv.FormatInt(a.server.clock().Unix(), 10)
		nonce := randomToken()
		mac := identity.MAC(a.passwordHash[:], "oimo/probe-admin-session/v1", []byte(issued), []byte(nonce))
		http.SetCookie(w, &http.Cookie{Name: "oimo_probe_admin", Value: issued + "." + nonce + "." + mac.String(), Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int((8 * time.Hour).Seconds())})
	case "/boards":
		if e := a.server.addBoard(f["key"], f["name"]); e != nil {
			a.show(w, r, 422, e.Error(), f["key"], f["name"])
			return
		}
	case "/logout":
		http.SetCookie(w, &http.Cookie{Name: "oimo_probe_admin", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
	http.Redirect(w, r, "/", 303)
}
