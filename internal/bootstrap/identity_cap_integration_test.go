// 実HTTPで回線分類・専ブラ命令・キャップ例外・鍵再発行・再起動を一つの投稿経路で検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/textcodec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIdentityMobileCapResetIntegration(t *testing.T) {
	cfg, r := adminFixture(t)
	useHealthyPostingCapacity(t, r)
	defer func() { r.Close() }()
	board, e := r.CreateBoard(context.Background(), "news", "回線表示")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	path := "/api/v1/boards/" + board.ID.String() + "/settings"
	res, body := c.request("GET", path, "", nil)
	var settings struct {
		Data AdminBoard `json:"data"`
	}
	if json.Unmarshal([]byte(body), &settings) != nil {
		t.Fatal(body)
	}
	edit := settings.Data.Settings
	edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "feature", AllowStrengthen: true, Networks: []identity.NetworkClass{{CIDR: "127.0.0.1/32", Kind: "mvno", Label: "ﾌﾞｰｲﾓ", Suffix: "M"}}}
	raw, _ := json.Marshal(edit)
	res, body = c.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"identity-settings-001"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	if res, page := c.request("GET", "/boards/"+board.ID.String()+"/settings", "", nil); res.StatusCode != 200 || !strings.Contains(page, "ワッチョイ") || !strings.Contains(page, "127.0.0.1/32") {
		t.Fatal(res.StatusCode, page)
	}
	// 旧APIのidentity省略更新は、登録済みの分類と表示を保持する。
	res, body = c.request("GET", path, "", nil)
	edit.Identity = nil
	raw, _ = json.Marshal(edit)
	res, body = c.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"identity-legacy-edit"}})
	if res.StatusCode != 200 || !strings.Contains(body, "127.0.0.1/32") {
		t.Fatal("identity erased by legacy edit", res.StatusCode, body)
	}
	form := formServer(t, r, siteID(r.site.State()), board.ID)
	defer func() { form.Close() }()
	first, e := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"識別試験"}, "MESSAGE": {"!extend:checked:vvvvv::\n本文"}, "oimo_request_id": {"identity-first-create"}})
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	snap, e := r.Thread(context.Background(), board.ID, first.Key)
	if e != nil || snap == nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(snap.DAT), "</b>") {
		t.Fatal("slip DAT", string(snap.DAT))
	}
	decoded, e := textcodec.Decode(snap.DAT)
	if e != nil || !strings.Contains(decoded, "ID:") || !strings.Contains(decoded, "M<") || !strings.Contains(decoded, "(ﾌﾞｰｲﾓ") || strings.Contains(decoded, "127.0.0.1") {
		t.Fatal(decoded, e)
	}
	policyResult, e := r.posting[board.ID].worker.Submit(context.Background(), func() (any, error) {
		p, ok := r.posting[board.ID].threads[first.Key].PostingPolicy(domain.Time(r.posting[board.ID].clock().UnixNano()))
		if !ok {
			return nil, fmt.Errorf("missing posting policy")
		}
		return p, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if policyResult.(domain.Policy).SlipMode != "vvvvv" {
		t.Fatal(policyResult)
	}
	addRule := func(input AdminRuleInput) {
		t.Helper()
		list, _ := c.rules(board.ID)
		raw, _ := json.Marshal(input)
		res, body := c.request("POST", "/api/v1/boards/"+board.ID.String()+"/rules", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {list.Header.Get("X-CSRF-Token")}, "If-Match": {list.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}})
		if res.StatusCode != 200 {
			t.Fatal("rule", res.StatusCode, body)
		}
	}
	addRule(AdminRuleInput{Target: "mobile", Operations: []string{"create", "reply"}, Minutes: 60, Reason: "manual", Match: &AdminRuleMatch{Field: "line", Operator: "exact", Effect: "deny"}})
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"一般投稿"}, "oimo_request_id": {"identity-denied-reply"}}
	if result, e := sendForm(form, reply); e != nil || result.Accepted {
		t.Fatal("mobile deny", result, e)
	}
	cap, secret := createTestCap(t, r, c, board.ID, []string{"create", "post"})
	reply.Set("mail", "sage #cap:"+cap.ID.String()+":"+secret)
	reply.Set("oimo_request_id", "identity-cap-post-001")
	if result, e := sendForm(form, reply); e != nil || !result.Accepted {
		t.Fatal("cap mobile exemption", result, e)
	}
	capSnapshot, e := r.Thread(context.Background(), board.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	capDAT, e := textcodec.Decode(capSnapshot.DAT)
	if e != nil || !strings.HasPrefix(strings.Split(capDAT, "\n")[1], "&lt;運営&gt; ★<>") {
		t.Fatal("blank name cap display", e)
	}
	addRule(AdminRuleInput{Target: "本文規制", Operations: []string{"reply"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{Field: "body", Operator: "contains", Effect: "deny"}})
	reply.Set("MESSAGE", "本文規制")
	reply.Set("oimo_request_id", "identity-cap-deny-001")
	if result, e := sendForm(form, reply); e != nil || result.Accepted {
		t.Fatal("cap content bypass", result, e)
	}
	capPath := "/api/v1/caps/" + cap.ID.String()
	get, _ := c.request("GET", capPath, "", nil)
	resetKey := "identity-cap-reset-01"
	res, replacement, newSecret, body := c.capChange(capPath+"/reset", struct{}{}, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Reset-Token"), resetKey)
	if res.StatusCode != 200 || len(newSecret) != 43 || replacement.ID == cap.ID || replacement.Expires != cap.Expires || !reflect.DeepEqual(replacement.Boards, cap.Boards) || !reflect.DeepEqual(replacement.Permissions, cap.Permissions) {
		t.Fatal("reset", res.StatusCode, body)
	}
	res, again, repeatedSecret, body := c.capChange(capPath+"/reset", struct{}{}, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Reset-Token"), resetKey)
	if res.StatusCode != 200 || again.ID != replacement.ID || repeatedSecret != "" || strings.Contains(body, newSecret) {
		t.Fatal("reset retry", res.StatusCode, body)
	}
	reply.Set("MESSAGE", "旧鍵")
	reply.Set("oimo_request_id", "identity-old-key-post")
	if result, e := sendForm(form, reply); e != nil || result.Accepted {
		t.Fatal("old cap accepted", result, e)
	}
	reply.Set("mail", "sage #cap:"+replacement.ID.String()+":"+newSecret)
	reply.Set("MESSAGE", "新しい鍵")
	reply.Set("oimo_request_id", "identity-new-key-post")
	if result, e := sendForm(form, reply); e != nil || !result.Accepted {
		t.Fatal("new cap", result, e)
	}
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "identity-cap-reset")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal(e)
	}
	form.Close()
	c.server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("restart after cap rotation", e)
	}
	useHealthyPostingCapacity(t, r)
	form = formServer(t, r, siteID(r.site.State()), board.ID)
	if result, e := sendForm(form, reply); e != nil || !result.Accepted || !result.Duplicate {
		t.Fatal("restored cap retry", result, e)
	}
	// 保存済みSLIPと旧キャップ投稿の原署名を新しい回線表・資格で再生成しない。
	snap, e = r.Thread(context.Background(), board.ID, first.Key)
	if e != nil || snap == nil || !strings.Contains(string(snap.DAT), "CAP_USER") {
		t.Fatal("restored data", e)
	}
}

// TestThreadSlipPolicyForm は管理HTMLの確認・確定から次のレスだけのIP公開までを検査する。
func TestThreadSlipPolicyForm(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	if e := r.EnableSlip(); e != nil {
		t.Fatal(e)
	}
	b, e := r.CreateBoard(context.Background(), "news", "表示変更")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	form := formServer(t, r, siteID(r.site.State()), b.ID)
	defer form.Close()
	created, e := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"題"}, "MESSAGE": {"元のレス"}, "oimo_request_id": {"identity-policy-create"}})
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	path := fmt.Sprintf("/boards/%s/threads/%d/actions", b.ID, created.Key)
	res, body := c.request("GET", path, "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	fields := threadPolicyFormFields(t, body, path)
	for k, v := range map[string]string{"step": "confirm", "kind": "update_policy", "target": "", "slip_mode": "vvvvvv", "id_mode": "required", "post_limit": "1000", "dat_limit": "524288"} {
		fields.Set(k, v)
	}
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, body = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "変更内容の確認") || !strings.Contains(body, "回線名・週ごとの識別子・IPアドレスを表示") {
		t.Fatal(res.StatusCode, body)
	}
	fields = pageFields(body)
	res, body = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "投稿の表示・上限を変更：反映済み") {
		t.Fatal(res.StatusCode, body)
	}
	reply, e := sendForm(form, url.Values{"bbs": {"news"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"新しいレス"}, "oimo_request_id": {"identity-policy-reply"}})
	if e != nil || !reply.Accepted {
		t.Fatal(reply, e)
	}
	snap, e := r.Thread(context.Background(), b.ID, created.Key)
	if e != nil || snap == nil {
		t.Fatal(e)
	}
	dat, e := textcodec.Decode(snap.DAT)
	lines := strings.Split(strings.TrimSuffix(dat, "\n"), "\n")
	if e != nil || len(lines) != 2 || strings.Contains(lines[0], "127.0.0.1") || !strings.Contains(lines[1], "</b>(ﾜｯﾁｮｲ ") || !strings.Contains(lines[1], "[127.0.0.1])<b>") {
		t.Fatal(dat, e)
	}

	// IP付きの設定からワッチョイだけへ変更すると、以後の投稿にIPが付かない。
	res, body = c.request("GET", path, "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `value="vvvvvv" selected`) || strings.Contains(body, `<select name="require_public_ip">`) {
		t.Fatal("display selection", res.StatusCode)
	}
	fields = threadPolicyFormFields(t, body, path)
	for k, v := range map[string]string{"step": "confirm", "kind": "update_policy", "target": "", "slip_mode": "vvvvv", "id_mode": "required", "post_limit": "1000", "dat_limit": "524288"} {
		fields.Set(k, v)
	}
	res, body = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "変更内容の確認") {
		t.Fatal("confirm wacchoi", res.StatusCode, body)
	}
	fields = pageFields(body)
	res, body = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "反映済み") {
		t.Fatal("apply wacchoi", res.StatusCode, body)
	}
	reply, e = sendForm(form, url.Values{"bbs": {"news"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"IPなしのレス"}, "oimo_request_id": {"identity-policy-no-ip"}})
	if e != nil || !reply.Accepted {
		t.Fatal(reply, e)
	}
	snap, e = r.Thread(context.Background(), b.ID, created.Key)
	if e != nil {
		t.Fatal(e)
	}
	dat, e = textcodec.Decode(snap.DAT)
	lines = strings.Split(strings.TrimSuffix(dat, "\n"), "\n")
	if e != nil || len(lines) != 3 || !strings.Contains(lines[1], "[127.0.0.1])<b>") || strings.Contains(lines[2], "127.0.0.1") || !strings.Contains(lines[2], "</b>(ﾜｯﾁｮｲ ") {
		t.Fatal(dat, e)
	}
}

// TestCapExemptionConditions は回線だけの拒否・Cookie条件と、内容混在/追加枠の境界を検査する。
func TestCapExemptionConditions(t *testing.T) {
	rows := map[domain.ID]denialRule{}
	pure := []denialRule{
		{Conditions: []denialCondition{{Field: "ip"}}, Effect: denialEffect{Type: "deny"}},
		{Conditions: []denialCondition{{Field: "network"}, {Field: "line"}}, Effect: denialEffect{Type: "require_token"}},
	}
	kept := []denialRule{
		{Conditions: []denialCondition{{Field: "line"}, {Field: "body"}}, Effect: denialEffect{Type: "deny"}},
		{Conditions: []denialCondition{{Field: "ua"}}, Effect: denialEffect{Type: "deny"}},
		{Conditions: []denialCondition{{Field: "network"}}, Effect: denialEffect{Type: "rate_override"}},
	}
	for _, v := range append(pure, kept...) {
		rows[domain.NewID()] = v
	}
	exemptCapConnectionRules(rows)
	if len(rows) != len(kept) {
		t.Fatal(rows)
	}
	for _, v := range rows {
		for _, p := range pure {
			if reflect.DeepEqual(v, p) {
				t.Fatal("pure connection rule retained")
			}
		}
	}
}

// TestCapResetFailedSave は新旧資格を配布する前の保存失敗で秘密を返さずwriterを停止する。
func TestCapResetFailedSave(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	b, e := r.CreateBoard(context.Background(), "news", "再発行失敗")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	cap, _ := createTestCap(t, r, c, b.ID, []string{"post"})
	path := "/api/v1/caps/" + cap.ID.String()
	get, _ := c.request("GET", path, "", nil)
	r.site.Close()
	res, _, secret, body := c.capChange(path+"/reset", struct{}{}, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Reset-Token"), "cap-reset-save-failed")
	if res.StatusCode != 503 || secret != "" || !strings.Contains(body, "SAVE_UNCERTAIN") {
		t.Fatal(res.StatusCode, body)
	}
	r.mu.Lock()
	stopped := r.stopped
	r.mu.Unlock()
	reg := r.liveCaps.Load()
	if !stopped || len(reg.Records) != 1 || !reg.Records[cap.ID].Enabled {
		t.Fatal("uncertain replacement published")
	}
}

// TestCapResetHTML は一覧の実フォームから新しいmail資格を初回だけ表示することを検査する。
func TestCapResetHTML(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	b, e := r.CreateBoard(context.Background(), "news", "鍵リセット画面")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	cap, _ := createTestCap(t, r, c, b.ID, []string{"post"})
	res, body := c.request("GET", "/caps", "", nil)
	path := "/caps/" + cap.ID.String() + "/reset"
	start := strings.Index(body, `<form action="`+path+`"`)
	if res.StatusCode != 200 || start < 0 {
		t.Fatal(res.StatusCode, body)
	}
	end := strings.Index(body[start:], "</form>")
	if end < 0 {
		t.Fatal("missing form end")
	}
	fields := pageFields(body[start : start+end])
	res, body = c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 || !strings.Contains(body, "#cap:") || !strings.Contains(body, "一度だけ表示") {
		t.Fatal(res.StatusCode, body)
	}
	res, body = c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 || strings.Contains(body, "#cap:") || !strings.Contains(body, "秘密は再表示しません") {
		t.Fatal(res.StatusCode, body)
	}
}
