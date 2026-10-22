// 実HTTPでメニュー→確認→スレ立て→返信→差分→再送を検証する。
package compatprobe

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/textcodec"
	"strconv"
	"strings"
	"testing"
)

func TestClientRoundtrip(t *testing.T) {
	s, e := New("http://localhost")
	if e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	s.base, _ = url.Parse(ts.URL)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	post := func(f url.Values) string {
		t.Helper()
		req, _ := http.NewRequest("POST", ts.URL+"/test/bbs.cgi", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		r, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		body, e := textcodec.Decode(b)
		if e != nil || r.StatusCode != 200 {
			t.Fatalf("status %d %s %v", r.StatusCode, body, e)
		}
		return body
	}
	f := url.Values{"bbs": {"oimo"}, "FROM": {"試験#A"}, "mail": {""}, "subject": {"日本語タイトル😀"}, "MESSAGE": {"本文\n<script> & 😀"}}
	if body := post(f); !strings.Contains(body, "2ch_X:cookie") || strings.Contains(body, "試験#A") {
		t.Fatal(body)
	}
	if body := post(f); !strings.Contains(body, "書きこみが終わりました。") {
		t.Fatal(body)
	}
	get := func(path string) ([]byte, http.Header) {
		t.Helper()
		r, e := client.Get(ts.URL + path)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal(path, r.StatusCode)
		}
		b, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		return b, r.Header
	}
	b, _ := get("/oimo/subject.txt")
	key := strings.SplitN(string(b), ".", 2)[0]
	before, headers := get("/oimo/dat/" + key + ".dat")
	plain, _ := textcodec.Decode(before)
	if !strings.Contains(plain, "◆hRJ9Ya./t.") || strings.Contains(plain, "<script>") {
		t.Fatal(plain)
	}
	if body := post(f); !strings.Contains(body, "受理済み") {
		t.Fatal(body)
	}
	f.Del("subject")
	f.Set("key", key)
	f.Set("MESSAGE", "返信")
	_ = post(f)
	if body := post(f); !strings.Contains(body, "書きこみが終わりました。") {
		t.Fatal(body)
	}
	after, _ := get("/oimo/dat/" + key + ".dat")
	if strings.Count(string(after), "\n") != 2 {
		t.Fatal("duplicate post")
	}
	req, _ := http.NewRequest("GET", ts.URL+"/oimo/dat/"+key+".dat", nil)
	req.Header.Set("Range", "bytes="+strconv.Itoa(len(before))+"-")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	tail, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 206 || string(append(before, tail...)) != string(after) {
		t.Fatal("range")
	}
	req, _ = http.NewRequest("GET", ts.URL+"/oimo/dat/"+key+".dat", nil)
	req.Header.Set("If-None-Match", headers.Get("ETag"))
	res, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_ = res.Body.Close()
	if res.StatusCode == 304 {
		t.Fatal("stale etag")
	}
	get("/test/read.cgi/oimo/" + key + "/1-2")
}
func TestRequestBoundaries(t *testing.T) {
	s, _ := New("http://localhost")
	for _, v := range []struct {
		Method, Path string
		Status       int
	}{{"POST", "/oimo/subject.txt", 405}, {"GET", "/test/bbs.cgi", 405}, {"POST", "/api/v1/admin", 404}, {"POST", "/test%2fbbs.cgi", 400}, {"POST", "/test//bbs.cgi", 400}, {"POST", "/test/../bbs.cgi", 400}} {
		r := httptest.NewRequest(v.Method, "http://localhost"+v.Path, nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != v.Status {
			t.Errorf("%s: %d", v.Path, w.Code)
		}
	}
}
