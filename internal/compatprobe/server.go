// Package compatprobe はP0専ブラ通信試験専用の揮発性サーバ。製品の保存経路には使用しない。
package compatprobe

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/textcodec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const BoardKey = "oimo"
const notice = "P0互換試験専用。投稿はメモリ上のみで、終了時に消えます。個人情報を投稿しないでください。"

var boardPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
var requestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

type row struct {
	Key      uint64
	Title    string
	Posts    []domain.Post
	DAT      []byte
	Revision uint64
	Modified time.Time
	DateSafe bool
	Bump     uint64
}
type receipt struct {
	Digest domain.Hash
	Key    uint64
	Number uint32
	Until  time.Time
}

// Server は試験板の公開窓口を持つ。rootだけが板ディレクトリを所有する。
type Server struct {
	mu      sync.Mutex
	base    *url.URL
	board   domain.ID
	key     []byte
	threads map[uint64]*row
	dedup   map[string]receipt
	last    uint64
	clock   func() time.Time
	slug    string
	name    string
	boards  map[string]*Server
}

// New は固定originの互換試験サーバを生成する。
func New(base string) (*Server, error) {
	u, e := url.Parse(base)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid base URL")
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	s := &Server{base: u, board: domain.NewID(), key: key, threads: map[uint64]*row{}, dedup: map[string]receipt{}, clock: time.Now, slug: BoardKey, name: "OimoBBS互換試験"}
	s.boards = map[string]*Server{BoardKey: s}
	return s, nil
}

// ServeHTTP は未登録Host・曖昧なpath・未対応メソッドを拒否する。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https: http: data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Cache-Control", "no-cache")
	if !strings.EqualFold(r.Host, s.base.Host) || badPath(r.URL) {
		http.Error(w, "invalid host or path", 400)
		return
	}
	if r.URL.Path == "/web/post" {
		s.webPost(w, r)
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/bbsmenu.html" && r.URL.Path != "/bbsmenu.json" && r.URL.Path != "/test/bbs.cgi" {
		target := s.boardForPath(r.URL.Path)
		if target == nil {
			http.NotFound(w, r)
			return
		}
		s = target
	}
	post := r.URL.Path == "/test/bbs.cgi"
	get := s.knownGET(r.URL.Path)
	if !post && !get {
		http.NotFound(w, r)
		return
	}
	if post && r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(405)
		return
	}
	if get && r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(405)
		return
	}
	if post {
		s.post(w, r)
		return
	}
	s.get(w, r)
}
func badPath(u *url.URL) bool {
	p := u.Path
	raw := strings.ToLower(u.EscapedPath())
	if strings.ContainsAny(p, "\\\x00") || strings.Contains(p, "//") || strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") {
		return true
	}
	for _, c := range strings.Split(p, "/") {
		if c == "." || c == ".." {
			return true
		}
	}
	return false
}
func (s *Server) knownGET(p string) bool {
	prefix := "/" + s.slug + "/"
	return p == "/" || p == "/bbsmenu.html" || p == "/bbsmenu.json" || p == prefix || p == prefix+"index.html" || p == prefix+"subback.html" || p == prefix+"subject.txt" || p == prefix+"SETTING.TXT" || p == prefix+"head.txt" || strings.HasPrefix(p, prefix+"dat/") || strings.HasPrefix(p, "/test/read.cgi/"+s.slug+"/")
}
func output(w http.ResponseWriter, r *http.Request, ct string, b []byte) {
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	if r.Method != "HEAD" {
		_, _ = w.Write(b)
	}
}
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/bbsmenu.json":
		b, _ := json.Marshal(map[string]any{"menu_list": []any{map[string]any{"category_name": "互換試験", "category_content": s.menuBoards()}}})
		output(w, r, "application/json; charset=UTF-8", b)
	case "/bbsmenu.html":
		var menu strings.Builder
		menu.WriteString(`<html><head><meta charset="Shift_JIS"></head><body><b>互換試験</b><br>`)
		for _, board := range s.menuBoards() {
			fmt.Fprintf(&menu, `<a href="%s">%s</a><br>`, html.EscapeString(board.URL), html.EscapeString(board.Name))
		}
		menu.WriteString(`</body></html>`)
		b, _ := textcodec.Encode(menu.String(), true)
		output(w, r, "text/html; charset=Shift_JIS", b)
	case "/" + s.slug + "/SETTING.TXT":
		b, _ := textcodec.Encode("BBS_TITLE="+s.name+"\nBBS_TITLE_ORIG="+s.name+"\nBBS_NONAME_NAME=名無しさん\nBBS_SUBJECT_COUNT=128\nBBS_NAME_COUNT=96\nBBS_MAIL_COUNT=64\nBBS_MESSAGE_COUNT=4096\nBBS_LINE_NUMBER=30\nBBS_FORCE_ID=checked\nBBS_DISP_MSEC=checked\n", true)
		output(w, r, "text/plain; charset=Shift_JIS", b)
	case "/" + s.slug + "/head.txt":
		b, _ := textcodec.Encode(notice, true)
		output(w, r, "text/plain; charset=Shift_JIS", b)
	case "/" + s.slug + "/subject.txt":
		s.mu.Lock()
		rows := s.rows()
		s.mu.Unlock()
		b, _ := compat.Subject(rows)
		output(w, r, "text/plain; charset=Shift_JIS", b)
	default:
		if strings.HasPrefix(r.URL.Path, "/"+s.slug+"/dat/") {
			s.dat(w, r)
			return
		}
		s.web(w, r)
	}
}
func (s *Server) rows() []compat.SubjectEntry {
	threads := make([]*row, 0, len(s.threads))
	for _, t := range s.threads {
		threads = append(threads, t)
	}
	sort.Slice(threads, func(i, j int) bool { return threads[i].Bump > threads[j].Bump })
	rows := make([]compat.SubjectEntry, 0, len(threads))
	for _, t := range threads {
		rows = append(rows, compat.SubjectEntry{Key: t.Key, Title: t.Title, Count: uint32(len(t.Posts))})
	}
	return rows
}
func parseKey(v string) (uint64, bool) {
	n, e := strconv.ParseUint(v, 10, 64)
	return n, e == nil && n > 0 && strconv.FormatUint(n, 10) == v
}
func (s *Server) dat(w http.ResponseWriter, r *http.Request) {
	v := strings.TrimPrefix(r.URL.Path, "/"+s.slug+"/dat/")
	if !strings.HasSuffix(v, ".dat") {
		http.NotFound(w, r)
		return
	}
	key, ok := parseKey(strings.TrimSuffix(v, ".dat"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	t := s.threads[key]
	if t == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	p := compat.Representation{DAT: bytes.Clone(t.DAT), ETagIdentity: fmt.Sprintf(`"%s-%d-1-%d-identity"`, s.board, key, t.Revision), ETagGzip: fmt.Sprintf(`"%s-%d-1-%d%s"`, s.board, key, t.Revision, compat.GzipETagSuffix), Modified: t.Modified, Now: s.clock(), DateSafe: t.DateSafe}
	s.mu.Unlock()
	compat.ServeDAT(w, r, p)
}

func (s *Server) post(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.base.Scheme+"://"+s.base.Host || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "origin denied", 403)
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil {
		http.Error(w, "body too large", 413)
		return
	}
	f, e := compat.ParseForm(b, r.Header.Get("Content-Type"), false)
	if e != nil {
		status := 400
		if e == compat.ErrCharset {
			status = 415
		}
		http.Error(w, "invalid form", status)
		return
	}
	target := s.boardByKey(f["bbs"])
	if target == nil {
		s.result(w, r, "error", "板がありません。", "")
		return
	}
	target.submitFields(w, r, f)
}

// submitFields はWebと専ブラの投稿検証・確認・受理を共有する。
func (s *Server) submitFields(w http.ResponseWriter, r *http.Request, f map[string]string) {
	if id := f["oimo_request_id"]; id != "" && !requestPattern.MatchString(id) {
		s.result(w, r, "error", "再送IDが不正です。", "")
		return
	}
	ipText, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		http.Error(w, "invalid peer", 400)
		return
	}
	ip, e := netip.ParseAddr(ipText)
	if e != nil || ip.Zone() != "" {
		http.Error(w, "invalid peer", 400)
		return
	}
	input, e := prepare(f)
	if e != nil {
		s.result(w, r, "error", "投稿内容を確認してください。", "")
		return
	}
	now := s.clock()
	digest := identity.MAC(s.key, "oimo/probe-request/v1", []byte(f["bbs"]), []byte(f["key"]), []byte(f["subject"]), []byte(f["FROM"]), []byte(f["mail"]), []byte(f["MESSAGE"]), []byte(f["oimo_request_id"]))
	confirm := abuse.Confirmation{Board: s.board, Terms: 1, Request: digest, Policy: identity.MAC(s.key, "oimo/probe-policy/v1"), Issued: now.Unix(), Expires: now.Unix() + 600}
	cookie, _ := r.Cookie("oimo_confirm")
	token := ""
	if cookie != nil {
		token = cookie.Value
	}
	if r.URL.Path == "/web/post" {
		token = f["oimo_confirm"]
	}
	if abuse.VerifyConfirmation(token, confirm, s.key, 1, now) != nil {
		token, _ := abuse.IssueConfirmation(confirm, s.key, 1)
		if r.URL.Path == "/web/post" {
			s.renderConfirmation(w, r, f, input, token)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "oimo_confirm", Value: token, Path: "/", MaxAge: 600, HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteLaxMode})
		s.result(w, r, "confirm", notice+" 内容を確認して再送してください。", "")
		return
	}
	s.accept(w, r, f, input, digest, ip, now)
}

type prepared struct{ Name, Trip, Mail, Body, Title string }

func prepare(f map[string]string) (prepared, error) {
	var p prepared
	name, secret, _ := strings.Cut(f["FROM"], "#")
	var e error
	p.Trip, e = identity.Trip(secret)
	if e != nil {
		return p, e
	}
	if p.Name, e = compat.Normalize(name, false, true); e != nil {
		return p, e
	}
	p.Name = strings.NewReplacer("◆", "◇", "★", "☆", "●", "○").Replace(p.Name)
	if p.Name == "" {
		p.Name = "名無しさん"
	}
	if p.Mail, e = compat.Normalize(f["mail"], false, false); e != nil {
		return p, e
	}
	if p.Body, e = compat.Normalize(f["MESSAGE"], true, true); e != nil {
		return p, e
	}
	if p.Title, e = compat.Normalize(f["subject"], false, true); e != nil {
		return p, e
	}
	if strings.TrimSpace(p.Body) == "" || strings.Count(p.Body, "\n")+1 > 60 {
		return p, compat.ErrForm
	}
	for _, v := range []struct {
		S   string
		Max int
	}{{p.Name, 96}, {p.Mail, 64}, {p.Body, 4096}, {p.Title, 128}} {
		b, e := textcodec.Encode(v.S, true)
		if e != nil || len(b) > v.Max {
			return p, compat.ErrForm
		}
	}
	return p, nil
}
func (s *Server) accept(w http.ResponseWriter, r *http.Request, f map[string]string, p prepared, digest domain.Hash, ip netip.Addr, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.dedup {
		if !now.Before(v.Until) {
			delete(s.dedup, k)
		}
	}
	subject := identity.MAC(s.key, "oimo/probe-subject/v1", s.board[:], []byte(ip.Unmap().String()))
	lookup := subject.String() + ":" + digest.String()
	ttl := 30 * time.Second
	if f["oimo_request_id"] != "" {
		id := identity.MAC(s.key, "oimo/probe-id/v1", []byte(f["oimo_request_id"]))
		lookup = subject.String() + ":" + id.String()
		ttl = 24 * time.Hour
	}
	if old, ok := s.dedup[lookup]; ok {
		if old.Digest != digest {
			s.result(w, r, "error", "同じ再送IDの内容が異なります。", "")
			return
		}
		s.result(w, r, "already", "同一内容を受理済みです。", s.link(old.Key, old.Number))
		return
	}
	if len(s.dedup) >= 1024 {
		s.result(w, r, "error", "互換試験の保存枠が満杯です。", "")
		return
	}
	var t *row
	create := f["key"] == ""
	if create {
		if p.Title == "" || len(s.threads) >= 100 {
			s.result(w, r, "error", "タイトルまたは試験スレッド上限を確認してください。", "")
			return
		}
		key := uint64(max(now.Unix(), 1))
		if key <= s.last {
			key = s.last + 1
		}
		t = &row{Key: key, Title: p.Title, DateSafe: true}
	} else {
		key, ok := parseKey(f["key"])
		if !ok || p.Title != "" || s.threads[key] == nil {
			s.result(w, r, "error", "スレッドがありません。", "")
			return
		}
		t = s.threads[key]
		if len(t.Posts) >= 1000 {
			s.result(w, r, "error", "スレッドは終了しています。", "")
			return
		}
	}
	id, _ := identity.DailyID(s.key, s.board, now, ip)
	post := domain.Post{Number: uint32(len(t.Posts) + 1), Name: p.Name, Mail: p.Mail, Body: p.Body, Kind: "user", Visibility: "visible", Created: domain.Time(now.UnixNano()), Identity: domain.Identity{Trip: p.Trip, ID: id, Suffix: "0", DateText: compat.DateText(now)}}
	line, e := compat.DAT(post, t.Title)
	if e != nil || len(t.DAT)+len(line) > 512<<10 {
		s.result(w, r, "error", "DAT上限を超えます。", "")
		return
	}
	if now.Before(t.Modified) {
		t.DateSafe = false
	}
	t.Posts = append(t.Posts, post)
	t.DAT = append(t.DAT, line...)
	t.Modified = now
	t.Revision++
	if create || !strings.EqualFold(strings.TrimSpace(p.Mail), "sage") {
		t.Bump = uint64(max(now.UnixNano(), int64(t.Bump)+1))
	}
	s.threads[t.Key] = t
	if create {
		s.last = t.Key
	}
	s.dedup[lookup] = receipt{digest, t.Key, post.Number, now.Add(ttl)}
	s.result(w, r, "posted", notice, s.link(t.Key, post.Number))
}
func (s *Server) link(key uint64, number uint32) string {
	return fmt.Sprintf("%s/test/read.cgi/%s/%d/%d", strings.TrimSuffix(s.base.String(), "/"), s.slug, key, number)
}
func (s *Server) result(w http.ResponseWriter, r *http.Request, kind, message, link string) {
	if r.URL.Path == "/web/post" {
		s.webResult(w, r, kind, message, link)
		return
	}
	b, e := compat.PostResult(kind, message, link)
	if e != nil {
		http.Error(w, "render failed", 500)
		return
	}
	output(w, r, "text/html; charset=Shift_JIS", b)
}
