// 実HTTPでCAP管理の認証・非公開性・再送・停止スレ・復旧を検証する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func TestCapCommandParsing(t *testing.T) {
	for _, tc := range []struct {
		body    string
		kind    string
		minutes uint32
	}{{">>1 !ban 30m", "ban", 30}, {">>2\n!ban 2h", "ban", 120}, {">>1 !ban 365d", "ban", 525600}, {">>1 !ban", "ban", permanentDenyMinutes}, {">>12 !delete", "delete", 0}, {">>1 !unban", "unban", 0}, {">>1 !stop", "stop", 0}} {
		c, candidate, err := parseCapCommand(tc.body)
		if err != nil || !candidate || c.Kind != tc.kind || c.Minutes != tc.minutes {
			t.Fatal(tc.body, c, candidate, err)
		}
	}
	for _, body := range []string{">>0 !ban", ">>01 !ban", ">>1 !ban 0m", ">>1 !ban -1h", ">>1 !ban 1s", ">>1 !ban 1h30m", ">>1 !ban 99999999999999999d", ">>1 !delete reason", ">>1 !unknown", "!ban", ">>1 !ban 01d"} {
		_, candidate, err := parseCapCommand(body)
		if !candidate || err == nil {
			t.Fatal("published malformed command", body)
		}
	}
	for _, body := range []string{"普通の文章", ">>1 !report 広告", "本文 !other"} {
		_, candidate, err := parseCapCommand(body)
		if candidate || err != nil {
			t.Fatal(body)
		}
	}
}

func TestCapCommandsHTTPAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	if err := repo.EnableSlip(); err != nil {
		t.Fatal(err)
	}
	board, err := repo.CreateBoard(t.Context(), "commands", "コマンド試験")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	c.login(adminTestSecret)
	c.reauth(adminTestSecret)
	cap, secret := createTestCap(t, repo, c, board.ID, []string{"post"})
	victim := formServer(t, repo, siteID(repo.site.State()), board.ID)
	first, err := sendForm(victim, url.Values{"bbs": {"commands"}, "subject": {"対象"}, "MESSAGE": {"ORIGINAL-COMMAND-TARGET"}, "oimo_request_id": {"victim-create-00001"}})
	if err != nil || !first.Accepted {
		t.Fatal("create", first, err)
	}
	manager := formServer(t, repo, siteID(repo.site.State()), board.ID)
	fields := url.Values{"bbs": {"commands"}, "key": {fmt.Sprint(first.Key)}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}, "MESSAGE": {">>1 !ban 30m"}, "oimo_request_id": {"command-ban-000001"}}
	run := func(body, id string) formResult {
		t.Helper()
		fields.Set("MESSAGE", body)
		fields.Set("oimo_request_id", id)
		result, err := sendForm(manager, fields)
		if err != nil || !result.Accepted {
			t.Fatal("command", body, result, err)
		}
		return result
	}
	run(">>1 !ban 30m", "command-ban-000001")
	if result := run(">>1 !ban 30m", "command-ban-000001"); !result.Duplicate {
		t.Fatal("ban retry")
	}
	denied, err := sendForm(victim, url.Values{"bbs": {"commands"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"denied reply"}, "oimo_request_id": {"victim-denied-0001"}})
	if err != nil || denied.Accepted {
		t.Fatal("ban not enforced", denied, err)
	}
	b := repo.posting[board.ID]
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		rules := b.sortedDenials()
		if len(rules) != 1 || rules[0].Expires-rules[0].Starts != domain.Time(30*time.Minute) {
			t.Error("duration", rules)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	run(">>1 !unban", "command-unban-00001")
	run(">>1 !ban", "command-permanent-001")
	// 古い解除の再送は、その後に作ったBANを解除しない。
	if result := run(">>1 !unban", "command-unban-00001"); !result.Duplicate {
		t.Fatal("unban retry")
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		active := 0
		for _, rule := range b.sortedDenials() {
			if rule.Enabled {
				active++
				if rule.Expires != permanentDenyExpiry {
					t.Error("not permanent")
				}
			}
		}
		if active != 1 {
			t.Error("unban replay", active)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	run(">>1 !unban", "command-unban-00002")
	run(">>1 !stop", "command-stop-000001")
	snapshot, err := repo.Thread(t.Context(), board.ID, first.Key)
	if err != nil || snapshot == nil || snapshot.PostCount != 2 || snapshot.CanReply {
		t.Fatal("stop", snapshot, err)
	}
	run(">>1 !ban 365d", "command-longban-001")
	run(">>1 !delete", "command-delete-0001")
	if result := run(">>1 !delete", "command-delete-0001"); !result.Duplicate {
		t.Fatal("delete retry")
	}
	// 板の返信も停止した状態でWebのCSRF・確認経路から管理操作を実行する。
	boardRes, boardView := c.board(board.ID.String())
	boardEdit := boardView.Settings
	boardEdit.Reply = "disabled"
	boardRaw, _ := json.Marshal(boardEdit)
	if res, body := c.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(boardRaw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {boardRes.Header.Get("X-CSRF-Token")}, "If-Match": {boardRes.Header.Get("ETag")}, "Idempotency-Key": {"command-disable-replies-001"}}); res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	csrf, err := repo.IssueWebCSRF(t.Context(), board.ID, "web_reply")
	if err != nil {
		t.Fatal(err)
	}
	fields.Set("MESSAGE", ">>1 !unban")
	fields.Set("csrf", csrf.Token)
	fields.Set("oimo_request_id", "command-web-unban-001")
	pending, err := sendWeb(manager, fields, []http.Cookie{*csrf.Cookie}, cfg.Public.BaseURL)
	if err != nil || pending.Confirmation == nil || !pending.Confirmation.Management {
		t.Fatal("Web command confirmation", pending, err)
	}
	webResult, err := sendWeb(manager, fields, []http.Cookie{*csrf.Cookie, {Name: "oimo_confirm", Value: pending.Confirmation.Token}}, cfg.Public.BaseURL)
	if err != nil || !webResult.Accepted {
		t.Fatal("Web command on stopped board", webResult, err)
	}
	fields.Del("csrf")
	snapshot, err = repo.Thread(t.Context(), board.ID, first.Key)
	if err != nil || snapshot.PostCount != 2 || strings.Contains(string(snapshot.DAT), "ORIGINAL-COMMAND-TARGET") || strings.Contains(string(snapshot.DAT), "!ban") || strings.Contains(string(snapshot.DAT), "!delete") {
		t.Fatal("public leak", snapshot, err)
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		journals := []*evidence.Journal{}
		for _, j := range b.journals {
			journals = append(journals, j)
		}
		rows, err := app.AcceptedRecordsForPost(journals, board.ID, domain.U64(first.Key), 1, "post", domain.Time(b.clock().UnixNano()), 1)
		if err != nil || len(rows) != 1 {
			t.Error("original lost", rows, err)
		} else {
			body, err := rows[0].ReportBody()
			if err != nil || !strings.Contains(body, "ORIGINAL-COMMAND-TARGET") {
				t.Error("original missing", body, err)
			}
		}
		h := b.control.HistoryHeader()
		h.BaseSeq = uint64(b.control.State().Seq)
		raw, err := store.EncodeControlSnapshot(h, b.control.State(), 6, snapshotBoardValue)
		if err != nil {
			return nil, err
		}
		_, err = store.DecodeControlSnapshot(raw, h, snapshotBoardValue)
		return nil, err
	})
	if err != nil {
		t.Fatal(err)
	}
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	if err := catchUpAuditFixture(repo, t.Context(), &budget); err != nil {
		t.Fatal("audit catchup", err)
	}
	res, audit := c.request("GET", "/api/v1/audit", "", nil)
	if res.StatusCode != 200 || !strings.Contains(audit, "cap_command_delete_applied") || !strings.Contains(audit, `"actor_kind":"cap"`) || strings.Contains(audit, secret) || strings.Contains(audit, "ORIGINAL-COMMAND-TARGET") {
		t.Fatal("audit", res.StatusCode, audit)
	}
	manager.Close()
	victim.Close()
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	manager = formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer manager.Close()
	if result := run(">>1 !delete", "command-delete-0001"); !result.Duplicate {
		t.Fatal("restart retry")
	}
}

func TestCapCommandRejectionsAndManual(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	if err := repo.EnableSlip(); err != nil {
		t.Fatal(err)
	}
	board, err := repo.CreateBoard(t.Context(), "rejectcommands", "拒否試験")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "othercommands", "担当外")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if res, _ := c.request("GET", "/manual", "", nil); res.StatusCode != 401 {
		t.Fatal("anonymous manual")
	}
	c.login(adminTestSecret)
	c.reauth(adminTestSecret)
	cap, secret := createTestCap(t, repo, c, board.ID, []string{"post"})
	creator, creatorSecret := createTestCap(t, repo, c, board.ID, []string{"create"})
	outsider, outsiderSecret := createTestCap(t, repo, c, other.ID, []string{"post"})
	fs := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer fs.Close()
	first, err := sendForm(fs, url.Values{"bbs": {"rejectcommands"}, "subject": {"対象"}, "MESSAGE": {"PUBLIC-ORIGINAL"}, "oimo_request_id": {"reject-create-001"}})
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	before, _ := repo.Thread(t.Context(), board.ID, first.Key)
	for i, tc := range []struct{ body, mail, key string }{
		{">>1 !delete", "", fmt.Sprint(first.Key)},
		{">>1 !delete", "#cap:" + creator.ID.String() + ":" + creatorSecret, fmt.Sprint(first.Key)},
		{">>1 !delete", "#cap:" + outsider.ID.String() + ":" + outsiderSecret, fmt.Sprint(first.Key)},
		{">>1 !delete", "#cap:" + cap.ID.String() + ":" + strings.Repeat("x", 43), fmt.Sprint(first.Key)},
		{">>1 !ban 0m", "#cap:" + cap.ID.String() + ":" + secret, fmt.Sprint(first.Key)},
		{">>999 !delete", "#cap:" + cap.ID.String() + ":" + secret, fmt.Sprint(first.Key)},
		{">>1 !delete", "#cap:" + cap.ID.String() + ":" + secret, ""},
	} {
		result, err := sendForm(fs, url.Values{"bbs": {"rejectcommands"}, "key": {tc.key}, "subject": {"新規コマンド拒否"}, "MESSAGE": {tc.body}, "mail": {tc.mail}, "oimo_request_id": {fmt.Sprintf("reject-command-%04d", i)}})
		if err != nil || result.Accepted {
			t.Fatal("accepted unauthorized", tc, result, err)
		}
	}
	after, _ := repo.Thread(t.Context(), board.ID, first.Key)
	if after.Revision != before.Revision || string(after.DAT) != string(before.DAT) {
		t.Fatal("rejections changed public thread")
	}
	// WebはCSRFを欠くコマンドでも副作用を起こさない。
	request, err := http.NewRequest("POST", fs.URL+"/web/post", strings.NewReader(url.Values{"bbs": {"rejectcommands"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {">>1 !delete"}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "127.0.0.1:9080"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	request.Header.Set("Origin", "http://127.0.0.1:9080")
	res, err := fs.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == 200 {
		t.Fatal("Web CSRF bypass")
	}
	result, err := sendForm(fs, url.Values{"bbs": {"rejectcommands"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {">>1 !stop"}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}, "oimo_request_id": {"reject-stop-00001"}})
	if err != nil || !result.Accepted {
		t.Fatal("stop", result, err)
	}
	ordinary, err := sendForm(fs, url.Values{"bbs": {"rejectcommands"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"ordinary CAP reply"}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}, "oimo_request_id": {"reject-normal-001"}})
	if err != nil || ordinary.Accepted {
		t.Fatal("normal stopped reply", ordinary, err)
	}
	res, page := c.request("GET", "/audit", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "CAP ID") || !strings.Contains(page, "完了") {
		t.Fatal("audit HTML", res.StatusCode, page)
	}
	// 下位の担当管理者でもマニュアルは利用できる。
	list, _ := c.request("GET", "/api/v1/administrators", "", nil)
	input := accountInput{Login: "manual.viewer", Display: "閲覧担当", Password: adminTestSecret, Access: AdministratorAccess{Role: "moderator", Boards: []domain.ID{board.ID}, Permissions: []string{}, Enabled: true}}
	if res, _, body := c.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String()); res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	viewer := newAdminClient(t, repo)
	defer viewer.server.Close()
	_, loginPage := viewer.request("GET", "/login", "", nil)
	loginFields := pageFields(loginPage)
	loginFields.Set("login", input.Login)
	loginFields.Set("password", input.Password)
	if res, _ := viewer.request("POST", "/login", loginFields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); res.StatusCode != 303 {
		t.Fatal("viewer login")
	}
	res, page = viewer.request("GET", "/manual", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "CAP専用・非公開の管理コマンド") || !strings.Contains(page, "!unban") || !strings.Contains(page, `href="#audit"`) {
		t.Fatal("manual", res.StatusCode, page)
	}

}

func TestCapCommandDeletionIntentRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	if err := repo.EnableSlip(); err != nil {
		t.Fatal(err)
	}
	board, err := repo.CreateBoard(t.Context(), "intentcommands", "削除中断")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	c.login(adminTestSecret)
	c.reauth(adminTestSecret)
	cap, secret := createTestCap(t, repo, c, board.ID, []string{"post"})
	fs := formServer(t, repo, siteID(repo.site.State()), board.ID)
	first, err := sendForm(fs, url.Values{"bbs": {"intentcommands"}, "subject": {"対象"}, "MESSAGE": {"DELETE-INTENT-ORIGINAL"}, "oimo_request_id": {"intent-create-001"}})
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	b := repo.posting[board.ID]
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		b.deletionCheckpoint = func(stage string) error {
			if stage == "deletion:intent" {
				return errors.New("injected interruption")
			}
			return nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fields := url.Values{"bbs": {"intentcommands"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {">>1 !delete"}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}, "oimo_request_id": {"intent-delete-001"}}
	result, err := sendForm(fs, fields)
	if err != nil || result.Accepted {
		t.Fatal("interruption accepted", result, err)
	}
	fs.Close()
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("recover", err)
	}
	fs = formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer fs.Close()
	result, err = sendForm(fs, fields)
	if err != nil || !result.Accepted {
		t.Fatal("resume", result, err)
	}
	snapshot, err := repo.Thread(t.Context(), board.ID, first.Key)
	if err != nil || snapshot == nil || snapshot.PostCount != 1 || strings.Contains(string(snapshot.DAT), "DELETE-INTENT-ORIGINAL") {
		t.Fatal("recovered public", snapshot, err)
	}
	again, err := sendForm(fs, fields)
	if err != nil || !again.Accepted || !again.Duplicate {
		t.Fatal("recovered duplicate", again, err)
	}
}

func TestCapCommandReceiptStrictTransitions(t *testing.T) {
	now := domain.Time(time.Now().UnixNano())
	v := capCommandReceipt{Key: domain.Hash{1}, Request: domain.Hash{2}, Cap: domain.NewID(), Board: domain.NewID(), Thread: 123, Post: 1, Kind: "ban", Minutes: 30, Rules: []domain.ID{}, Created: now, Expires: now + 86400e9}
	raw, _ := json.Marshal(v)
	if err := validateCapCommandReceipt(v.Key.String(), nil, raw); err != nil {
		t.Fatal(err)
	}
	v.Done = true
	done, _ := json.Marshal(v)
	if err := validateCapCommandReceipt(v.Key.String(), raw, done); err != nil {
		t.Fatal(err)
	}
	if validateCapCommandReceipt(v.Key.String(), nil, done) == nil || validateCapCommandReceipt(v.Key.String(), done, raw) == nil {
		t.Fatal("invalid phase accepted")
	}
	if err := snapshotCapCommandReceipt(v.Key.String(), done); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{strings.Replace(string(raw), `"done":false`, `"done":false,"unknown":true`, 1), strings.Replace(string(raw), `"done":false`, `"done":null`, 1), strings.Replace(string(raw), `"done":false`, `"done":false,"done":false`, 1), strings.Replace(string(raw), `"done":false,`, "", 1)} {
		if validateCapCommandReceipt(v.Key.String(), nil, []byte(body)) == nil {
			t.Fatal("invalid JSON accepted", body)
		}
	}
	fields := map[string]json.RawMessage{}
	_ = json.Unmarshal(done, &fields)
	fields["post_number"] = json.RawMessage("2")
	changed, _ := json.Marshal(fields)
	if validateCapCommandReceipt(v.Key.String(), raw, changed) == nil {
		t.Fatal("changed target accepted")
	}
	// 完了済みの短命行は回収でき、監査は別の保存期限で残る。
	state := store.ControlState{Rows: map[string]store.ControlRow{"cap_command:" + v.Key.String(): {Revision: 2, Value: done}}}
	names, err := expiredControlNames(state, 2, v.Expires)
	if err != nil || len(names) != 1 {
		t.Fatal("receipt expiry", names, err)
	}
}

func TestCapCommandImplicitReplayBoundary(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	if err := repo.EnableSlip(); err != nil {
		t.Fatal(err)
	}
	board, err := repo.CreateBoard(t.Context(), "implicitcommands", "暗黙再送")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	c.reauth(adminTestSecret)
	cap, secret := createTestCap(t, repo, c, board.ID, []string{"post"})
	victim := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer victim.Close()
	first, err := sendForm(victim, url.Values{"bbs": {"implicitcommands"}, "subject": {"対象"}, "MESSAGE": {"ORIGINAL"}})
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	fs := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer fs.Close()
	fields := url.Values{"bbs": {"implicitcommands"}, "key": {fmt.Sprint(first.Key)}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}, "MESSAGE": {">>1 !unban"}}
	firstUnban, err := sendForm(fs, fields)
	if err != nil || !firstUnban.Accepted || firstUnban.Duplicate {
		t.Fatal("first implicit", firstUnban, err)
	}
	fields.Set("MESSAGE", ">>1 !ban 30m")
	fields.Set("oimo_request_id", "implicit-new-ban-001")
	banned, err := sendForm(fs, fields)
	if err != nil || !banned.Accepted {
		t.Fatal(banned, err)
	}
	fields.Set("MESSAGE", ">>1 !unban")
	fields.Del("oimo_request_id")
	retry, err := sendForm(fs, fields)
	if err != nil || !retry.Accepted || !retry.Duplicate {
		t.Fatal("implicit retry", retry, err)
	}
	b := repo.posting[board.ID]
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		if len(b.sortedDenials()) != 1 || !b.sortedDenials()[0].Enabled {
			t.Error("retry undid later ban")
		}
		b.clock = func() time.Time { return time.Now().Add(31 * time.Second) }
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	later, err := sendForm(fs, fields)
	if err != nil || !later.Accepted || later.Duplicate {
		t.Fatal("fresh implicit", later, err)
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		if b.sortedDenials()[0].Enabled {
			t.Error("fresh command did not lift ban")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
