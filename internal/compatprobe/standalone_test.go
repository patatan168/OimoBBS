// 試験サーバ単独の管理者による板作成と一般投稿の境界を検証する。
package compatprobe

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func hiddenValue(t *testing.T, body, name string) string {
	t.Helper()
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	m := re.FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatalf("missing field %s in %s", name, body)
	}
	return html.UnescapeString(m[1])
}
func TestStandaloneBoardAndPosting(t *testing.T) {
	s, _ := New("http://localhost")
	pub := httptest.NewServer(s)
	defer pub.Close()
	s.base, _ = url.Parse(pub.URL)
	admin, err := s.AdminHandler("http://localhost:9081", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	adm := httptest.NewServer(admin)
	defer adm.Close()
	admin.origin, _ = url.Parse(adm.URL)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(u string) string {
		t.Helper()
		r, e := client.Get(u)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		if r.Header.Get("Referrer-Policy") != "same-origin" {
			t.Fatal("browser POST requires same-origin referrer policy")
		}
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatal(r.StatusCode, string(b))
		}
		return string(b)
	}
	sendOrigin := func(base, path, origin string, f url.Values, want int) string {
		t.Helper()
		req, _ := http.NewRequest("POST", base+path, strings.NewReader(f.Encode()))
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		r, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != want {
			t.Fatalf("%s got %d want %d: %s", path, r.StatusCode, want, b)
		}
		if want == 303 {
			return r.Header.Get("Location")
		}
		return string(b)
	}
	send := func(base, path string, f url.Values, want int) string {
		t.Helper()
		return sendOrigin(base, path, base, f, want)
	}
	send(pub.URL, "/boards", url.Values{"key": {"newboard"}}, 404)
	send(adm.URL, "/boards", url.Values{"key": {"newboard"}}, 401)
	login := get(adm.URL + "/")
	loginFields := url.Values{"csrf": {hiddenValue(t, login, "csrf")}, "password": {strings.Repeat("b", 64)}}
	send(adm.URL, "/login", loginFields, 401)
	loginFields.Set("password", strings.Repeat("a", 64))
	sendOrigin(adm.URL, "/login", pub.URL, loginFields, 403)
	send(adm.URL, "/login", url.Values{"password": {strings.Repeat("a", 64)}}, 403)
	send(adm.URL, "/login", url.Values{"csrf": {hiddenValue(t, login, "csrf")}, "password": {strings.Repeat("a", 64)}}, 303)
	panel := get(adm.URL + "/")
	send(adm.URL, "/boards", url.Values{"csrf": {hiddenValue(t, panel, "csrf")}, "key": {"newboard"}, "name": {"新しい板"}}, 303)
	boardFields := url.Values{"csrf": {hiddenValue(t, panel, "csrf")}, "key": {"newboard"}, "name": {"新しい板"}}
	send(adm.URL, "/boards", boardFields, 422)
	for _, key := range []string{"test", "web", "../bad", "Upper"} {
		boardFields.Set("key", key)
		send(adm.URL, "/boards", boardFields, 422)
	}
	boardFields.Set("key", "rejected")
	sendOrigin(adm.URL, "/boards", pub.URL, boardFields, 403)
	home := get(pub.URL + "/")
	if !strings.Contains(home, `href="/newboard/"`) {
		t.Fatal("created board absent")
	}
	if strings.Contains(home, `action="/boards"`) {
		t.Fatal("public board creation")
	}
	var menu struct {
		List []struct {
			Content []map[string]string `json:"category_content"`
		} `json:"menu_list"`
	}
	if err := json.Unmarshal([]byte(get(pub.URL+"/bbsmenu.json")), &menu); err != nil {
		t.Fatal(err)
	}
	if len(menu.List) != 1 || len(menu.List[0].Content) != 2 {
		t.Fatal("menu directory differs")
	}
	for _, b := range menu.List[0].Content {
		if len(b) != 2 {
			t.Fatal("menu fields changed", b)
		}
	}
	board := get(pub.URL + "/newboard/")
	fields := url.Values{"bbs": {"newboard"}, "FROM": {"名無しさん"}, "mail": {""}, "subject": {"単独テスト"}, "MESSAGE": {"はじめまして"}, "oimo_request_id": {hiddenValue(t, board, "oimo_request_id")}, "csrf": {hiddenValue(t, board, "csrf")}}
	sendOrigin(pub.URL, "/web/post", adm.URL, fields, 403)
	fields.Set("bbs", "oimo")
	send(pub.URL, "/web/post", fields, 403)
	fields.Set("bbs", "newboard")
	fields.Set("FROM", "投稿者#private-secret")
	fields.Set("MESSAGE", "")
	invalid := send(pub.URL, "/web/post", fields, 422)
	if strings.Contains(invalid, "private-secret") || !strings.Contains(invalid, "単独テスト") {
		t.Fatal("error form lost input or exposed secret")
	}
	fields.Set("FROM", "投稿者#A")
	fields.Set("MESSAGE", "最初の確認本文")
	confirm := send(pub.URL, "/web/post", fields, 200)
	fields.Set("oimo_confirm", hiddenValue(t, confirm, "oimo_confirm"))
	fields.Set("MESSAGE", "はじめまして")
	confirm = send(pub.URL, "/web/post", fields, 200)
	if body := get(pub.URL + "/newboard/subject.txt"); body != "" {
		t.Fatal("changed content bypassed confirmation")
	}
	fields.Set("oimo_confirm", hiddenValue(t, confirm, "oimo_confirm"))
	location := send(pub.URL, "/web/post", fields, 303)
	if got := send(pub.URL, "/web/post", fields, 303); got != location {
		t.Fatal("duplicate post")
	}
	thread := get(location)
	if !strings.Contains(thread, "◆hRJ9Ya./t.") || !strings.Contains(thread, " ID:") {
		t.Fatal("public identity absent")
	}
	if !strings.Contains(thread, "はじめまして") {
		t.Fatal("post absent")
	}
	reply := url.Values{"bbs": {"newboard"}, "key": {hiddenValue(t, thread, "key")}, "FROM": {"返信者"}, "mail": {"sage"}, "MESSAGE": {"返信本文"}, "oimo_request_id": {hiddenValue(t, thread, "oimo_request_id")}, "csrf": {hiddenValue(t, thread, "csrf")}}
	confirm = send(pub.URL, "/web/post", reply, 200)
	reply.Set("oimo_confirm", hiddenValue(t, confirm, "oimo_confirm"))
	location = send(pub.URL, "/web/post", reply, 303)
	if !strings.Contains(get(location), "返信本文") {
		t.Fatal("reply absent")
	}
	if body := get(pub.URL + "/oimo/subject.txt"); body != "" {
		t.Fatal("cross-board leakage")
	}
	send(pub.URL, "/web/post", url.Values{"bbs": {"newboard"}, "MESSAGE": {"forged"}}, 403)
	send(adm.URL, "/logout", url.Values{"csrf": {hiddenValue(t, panel, "csrf")}}, 303)
	send(adm.URL, "/boards", boardFields, 401)
}
