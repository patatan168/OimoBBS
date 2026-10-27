// 状態別集計、全件検索、カーソルと検索条件の束縛を検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/url"
	"oimobbs/internal/domain"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRegisteredRuleListSearchAcrossPages(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "rulelist", "規制一覧")
	if err != nil {
		t.Fatal(err)
	}
	b := repo.posting[board.ID]
	now := domain.Time(time.Now().UnixNano())
	// 表示用fixtureは板workerの所有権の下で作り、実運用の保存領域へは追加しない。
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		for i := range 65 {
			starts := now - domain.Time(i+1)*1e9
			expires := now + 3600e9
			enabled := true
			if i%3 == 1 {
				expires = now - 1e9
			}
			if i%3 == 2 {
				enabled = false
			}
			revision := domain.U64(1)
			if !enabled {
				revision = 2
			}
			rule := denialRule{ID: domain.NewID(), Revision: revision, Scope: denialScope{"board", board.ID}, Operations: []string{"create", "reply"}, Conditions: []denialCondition{{"body", "contains", fmt.Sprintf("一覧確認-%02d", i), "deny"}}, Effect: denialEffect{Type: "deny"}, Starts: starts, Expires: expires, Reason: "spam", Enabled: enabled}
			compiled, compileErr := compileDenial(rule)
			if compileErr != nil {
				return nil, compileErr
			}
			b.denials[rule.ID] = compiled
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	action := "/boards/" + board.ID.String() + "/rules"
	res, body := c.request("GET", action, "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "rule-table") || !strings.Contains(body, "すべて <strong>65</strong>") {
		t.Fatal(res.StatusCode, body)
	}
	res, body = c.request("GET", action+"?q="+url.QueryEscape("一覧確認-64"), "", nil)
	if res.StatusCode != 200 || strings.Count(body, "data-rule-state=") != 1 || !strings.Contains(body, "一覧確認-64") {
		t.Fatal("search beyond page", res.StatusCode, body)
	}
	res, body = c.request("GET", action+"?state=revoked", "", nil)
	if res.StatusCode != 200 || strings.Contains(body, `data-rule-state="active"`) || strings.Count(body, `data-rule-state="revoked"`) != 21 {
		t.Fatal("revoked filter", res.StatusCode, body)
	}
	res, _ = c.request("GET", action+"?state=unknown", "", nil)
	if res.StatusCode != 400 {
		t.Fatal("invalid filter", res.StatusCode)
	}
	path := "/api/v1" + action
	res, body = c.request("GET", path+"?limit=1&state=active", "", nil)
	var page struct {
		Next string `json:"next_cursor"`
	}
	if err = json.Unmarshal([]byte(body), &page); err != nil || res.StatusCode != 200 || page.Next == "" {
		t.Fatal("cursor", res.StatusCode, body, err)
	}
	res, _ = c.request("GET", path+"?state=revoked&cursor="+url.QueryEscape(page.Next), "", nil)
	if res.StatusCode != 400 {
		t.Fatal("cursor filter mismatch", res.StatusCode)
	}
}

// ruleCreateFields は一覧の検索・解除フォームと区別して、登録フォームの値を読み取る。
func ruleCreateFields(t *testing.T, page string) url.Values {
	t.Helper()
	form := regexp.MustCompile(`(?s)<form data-rule-create[^>]*>.*?</form>`).FindString(page)
	if form == "" {
		t.Fatal("規制の登録フォームがありません")
	}
	return pageFields(form)
}
