// 信頼済みHTTP観測のUser-Agent値を規制へ接続し、重複ヘッダと欠落・復旧を検査する。
package bootstrap

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
)

func sendUAForm(server *httptest.Server, fields url.Values, agents []string) (formResult, error) {
	token := ""
	var last formResult
	for range 2 {
		req, e := http.NewRequest("POST", server.URL+"/test/bbs.cgi", nil)
		if e != nil {
			return formResult{}, e
		}
		// net/httpのclient writerはUser-Agentを一個にするため、実際に複数行を
		// サーバへ渡すこの試験だけはHTTP/1のヘッダを直接送る。
		address, _ := url.Parse(server.URL)
		conn, e := net.DialTimeout("tcp", address.Host, 5*time.Second)
		if e != nil {
			return formResult{}, e
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		var raw strings.Builder
		fmt.Fprintf(&raw, "POST /test/bbs.cgi HTTP/1.1\r\nHost: 127.0.0.1:9080\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n", len(fields.Encode()))
		for _, agent := range agents {
			fmt.Fprintf(&raw, "User-Agent: %s\r\n", agent)
		}
		cookieValues := []string{}
		if token != "" {
			cookieValues = append(cookieValues, "oimo_confirm="+token)
		}
		if server.Client().Jar != nil {
			for _, cookie := range server.Client().Jar.Cookies(address) {
				cookieValues = append(cookieValues, cookie.Name+"="+cookie.Value)
			}
		}
		if len(cookieValues) > 0 {
			fmt.Fprintf(&raw, "Cookie: %s\r\n", strings.Join(cookieValues, "; "))
		}
		raw.WriteString("\r\n" + fields.Encode())
		if _, e := fmt.Fprint(conn, raw.String()); e != nil {
			conn.Close()
			return formResult{}, e
		}
		res, e := http.ReadResponse(bufio.NewReader(conn), req)
		if e != nil {
			conn.Close()
			return formResult{}, e
		}
		if server.Client().Jar != nil {
			server.Client().Jar.SetCookies(address, res.Cookies())
		}
		var result formResult
		e = json.NewDecoder(res.Body).Decode(&result)
		last = result
		for _, cookie := range res.Cookies() {
			if cookie.Name == "oimo_confirm" {
				token = cookie.Value
			}
		}
		res.Body.Close()
		conn.Close()
		if e != nil || result.Confirmation == nil {
			return result, e
		}
	}
	return last, nil
}

func TestUARuleHTTPDuplicateHeadersAndRecovery(t *testing.T) {
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := c.rules(board)
	input := AdminRuleInput{Target: "SpamClient", Operations: []string{"create"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"ua", "contains", "deny"}}
	raw, _ := json.Marshal(input)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"ua-rule-save-0000001"}}
	res, body := c.request("POST", "/api/v1/boards/"+board.String()+"/rules", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("UA rule", res.StatusCode, body)
	}
	server := formServer(t, repo, siteID(repo.site.State()), board, true)
	defer server.Close()
	fields := url.Values{"bbs": {"news"}, "subject": {"UA試験"}, "MESSAGE": {"本文"}, "oimo_request_id": {"ua-post-denied-00001"}}
	// 匿名Cookie発行だけを済ませ、UA規制の判定を検証する。
	if result, e := sendFormOnce(server, fields, ""); e != nil || result.Accepted || result.Confirmation == nil {
		t.Fatal("Cookie setup", result, e)
	}
	result, e := sendUAForm(server, fields, []string{"OrdinaryClient", "SpamClient/1.0"})
	if e != nil || result.Accepted || result.Confirmation != nil {
		t.Fatal("duplicate UA bypass", result, e)
	}
	rows, e := repo.rateHistory()
	if e != nil || len(rows) != 0 {
		t.Fatal("denied operation saved", e)
	}
	fields.Set("oimo_request_id", "ua-post-accepted0001")
	result, e = sendUAForm(server, fields, []string{"OrdinaryClient"})
	if e != nil || !result.Accepted {
		t.Fatal("ordinary UA denied", result, e)
	}
	c.server.Close()
	server.Close()
	installRuntimeFixture(t, cfg, repo, 20)
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("UA recovery", e)
	}
	observed := []evidence.ObservedHeader{{Name: "User-Agent", Values: []evidence.HeaderValue{{Display: "SpamClient/1.0"}}}}
	denied, _, e := repo.posting[board].matchingObservedRules(netip.MustParseAddr("127.0.0.1"), postinput.Input{}, domain.Hash{}, true, domain.Time(time.Now().UnixNano()), observed)
	if e != nil || !denied {
		t.Fatal("UA matcher lost", e)
	}
}

func TestUARuleMissingValueAndAND(t *testing.T) {
	now := domain.Time(time.Now().UnixNano())
	rule := denialRule{domain.NewID(), 1, denialScope{"board", domain.NewID()}, []string{"reply"}, []denialCondition{{"ua", "regexp", "^$", "deny"}, {"body", "contains", "禁止", "deny"}}, denialEffect{Type: "deny"}, 0, now, now + domain.Time(time.Minute), "spam", true, nil, nil}
	compiled, e := compileDenial(rule)
	if e != nil {
		t.Fatal(e)
	}
	b := &postingBoard{denials: map[domain.ID]compiledDenial{rule.ID: compiled}}
	denied, _, e := b.matchingObservedRules(netip.MustParseAddr("192.0.2.1"), postinput.Input{Body: "禁止"}, domain.Hash{}, false, now, nil)
	if e != nil || !denied {
		t.Fatal("missing UA", e)
	}
	denied, _, e = b.matchingObservedRules(netip.MustParseAddr("192.0.2.1"), postinput.Input{Body: "普通"}, domain.Hash{}, false, now, nil)
	if e != nil || denied {
		t.Fatal("AND mismatch", e)
	}
}
