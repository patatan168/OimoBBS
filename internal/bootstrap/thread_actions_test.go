// 管理変更の実HTTP、固定再送、各停止点からの復旧と公開効果を確認する。
package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func TestThreadActionsHTTPRecovery(t *testing.T) {
	for _, kind := range []string{"stop", "archive", "move_link", "update_policy"} {
		for _, stop := range []string{"", "action:intent", "action:thread", "action:applied"} {
			t.Run(kind+"/"+stop, func(t *testing.T) {
				cfg, repo := adminFixture(t)
				defer func() { repo.Close() }()
				board, err := repo.CreateBoard(context.Background(), "news", "ニュース")
				if err != nil {
					t.Fatal(err)
				}
				client := newAdminClient(t, repo)
				defer func() { client.server.Close() }()
				if client.login(adminTestSecret) != 303 {
					t.Fatal("login")
				}
				form := formServer(t, repo, siteID(repo.site.State()), board.ID)
				defer func() { form.Close() }()
				created, err := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"state title"}, "MESSAGE": {"preserved body"}, "oimo_request_id": {"thread-action-create-001"}})
				if err != nil || !created.Accepted {
					t.Fatal(created, err)
				}
				path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/actions", board.ID, created.Key)
				res, body := client.request("GET", path, "", nil)
				if res.StatusCode != 200 {
					t.Fatal(res.StatusCode, body)
				}
				var envelope struct {
					Data threadActionView `json:"data"`
				}
				if json.Unmarshal([]byte(body), &envelope) != nil {
					t.Fatal(body)
				}
				originalExpiry := envelope.Data.Expires
				edit := AdminThreadAction{Kind: kind}
				if kind == "move_link" {
					edit.Target = "https://example.invalid/thread/123?x=1&y=2"
				}
				if kind == "update_policy" {
					p := envelope.Data.Policy
					p.IDMode, p.RequireID, p.UserPostLimit = "hidden", false, 100
					p.Commands = []string{}
					edit.Policy = &p
				}
				raw, _ := json.Marshal(edit)
				headers := http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"thread-action-request-001"}}
				repo.posting[board.ID].deletionCheckpoint = func(stage string) error {
					if stop != "" && stage == stop {
						return errors.New("simulated interruption")
					}
					return nil
				}
				res, body = client.request("POST", path, string(raw), headers)
				if stop == "" && res.StatusCode != 200 || stop != "" && res.StatusCode != 503 {
					t.Fatal(res.StatusCode, body)
				}
				form.Close()
				client.server.Close()
				if err = repo.Close(); err != nil {
					t.Fatal(err)
				}
				repo, err = OpenPostingRepository(cfg, postcapture.Validate)
				if err != nil {
					t.Fatal("restart", err)
				}
				client = newAdminClient(t, repo)
				if client.login(adminTestSecret) != 303 {
					t.Fatal("relogin")
				}
				res, body = client.request("GET", path, "", nil)
				if res.StatusCode != 200 || json.Unmarshal([]byte(body), &envelope) != nil || envelope.Data.Revision != 2 || envelope.Data.Expires != originalExpiry || len(envelope.Data.Actions) != 1 || envelope.Data.Actions[0].Phase != "applied" {
					t.Fatal(res.StatusCode, body)
				}
				action := envelope.Data.Actions[0]
				if action.CreatedAt == "" || action.ExpiresAt != originalExpiry || action.Revision != envelope.Data.Revision {
					t.Fatal("action dates or revision", action)
				}
				if _, e := time.Parse(time.RFC3339Nano, action.CreatedAt); e != nil {
					t.Fatal(e)
				}
				htmlRes, html := client.request("GET", strings.TrimPrefix(path, "/api/v1"), "", nil)
				if htmlRes.StatusCode != 200 || !strings.Contains(html, "操作履歴") || !strings.Contains(html, action.ID.String()) || !strings.Contains(html, action.CreatedAt) || !strings.Contains(html, "反映済み") {
					t.Fatal("action history", htmlRes.StatusCode, html)
				}
				headers.Set("X-CSRF-Token", res.Header.Get("X-CSRF-Token"))
				res, body = client.request("POST", path, string(raw), headers)
				if res.StatusCode != 200 {
					t.Fatal("retry", res.StatusCode, body)
				}
				conflict := headers.Clone()
				conflict.Set("If-Match", `"different"`)
				res, _ = client.request("POST", path, string(raw), conflict)
				if res.StatusCode != 409 {
					t.Fatal("reused request changed", res.StatusCode)
				}
				snapshot, err := repo.Thread(context.Background(), board.ID, created.Key)
				if err != nil || snapshot == nil || snapshot.Revision != 2 || !strings.Contains(string(snapshot.DAT), "preserved body") {
					t.Fatal(snapshot, err)
				}
				switch kind {
				case "stop":
					if snapshot.CanReply || snapshot.PostCount != 2 {
						t.Fatal(snapshot)
					}
				case "archive":
					rows, err := repo.threadListing(httptest.NewRequest("GET", "http://localhost/news/", nil), board.ID)
					if err != nil || len(rows) != 0 || snapshot.CanReply {
						t.Fatal("archive listed", rows, err)
					}
					recorder := httptest.NewRecorder()
					repo.SiteWebHandler(nil).ServeHTTP(recorder, httptest.NewRequest("GET", cfg.Public.BaseURL+"/news/", nil))
					if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "現役スレッドはありません") || !strings.Contains(recorder.Body.String(), "state=archived") {
						t.Fatal("archive empty page", recorder.Code, recorder.Body.String())
					}
				case "move_link":
					if snapshot.MoveTarget != edit.Target {
						t.Fatal(snapshot)
					}
					recorder := httptest.NewRecorder()
					req := httptest.NewRequest("GET", cfg.Public.BaseURL+fmt.Sprintf("/test/read.cgi/news/%d/", created.Key), nil)
					repo.threadPage(recorder, req, board.ID)
					if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "移転先のスレッド") || !strings.Contains(recorder.Body.String(), "x=1&amp;y=2") {
						t.Fatal("move page", recorder.Code, recorder.Body.String())
					}
				case "update_policy":
					if envelope.Data.Policy.IDMode != "hidden" || envelope.Data.Policy.Version != 2 {
						t.Fatal(envelope.Data.Policy)
					}
				}
				log := repo.posting[board.ID].deletions[created.Key]
				for name, row := range log.State().Rows {
					if strings.HasPrefix(name, "thread_action:") && strings.Contains(string(row.Value), "preserved body") {
						t.Fatal("old body copied into intent")
					}
				}
			})
		}
	}
}

func TestThreadActionsValidation(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(context.Background(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	client.login(adminTestSecret)
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	created, err := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"test"}, "MESSAGE": {"body"}, "oimo_request_id": {"thread-validation-create"}})
	if err != nil || !created.Accepted {
		t.Fatal(err, created)
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/actions", board.ID, created.Key)
	res, body := client.request("GET", path, "", nil)
	var envelope struct {
		Data threadActionView `json:"data"`
	}
	json.Unmarshal([]byte(body), &envelope)
	headers := http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"thread-validation-request"}}
	for _, tc := range []struct {
		raw    string
		status int
	}{
		{`{"kind":"stop","target":"unexpected","policy":null}`, 422},
		{`{"kind":"move_link","target":"javascript:alert(1)","policy":null}`, 422},
		{`{"kind":"archive","target":"","policy":null,"unknown":1}`, 400},
		{`{"kind":"stop","target":""}`, 400},
	} {
		res, body := client.request("POST", path, tc.raw, headers)
		if res.StatusCode != tc.status {
			t.Fatal(res.StatusCode, body)
		}
	}
	p := envelope.Data.Policy
	p.AutoNext = true
	raw, _ := json.Marshal(AdminThreadAction{Kind: "update_policy", Policy: &p})
	res, _ = client.request("POST", path, string(raw), headers)
	if res.StatusCode != 422 {
		t.Fatal("unsupported policy", res.StatusCode)
	}
	headers.Del("If-Match")
	res, _ = client.request("POST", path, `{"kind":"archive","target":"","policy":null}`, headers)
	if res.StatusCode != 428 {
		t.Fatal(res.StatusCode)
	}
	// 固定frame・actor・所有先の改変を保存前に拒否する。
	records, _ := repo.posting[board.ID].threadActions()
	if len(records) != 0 {
		t.Fatal(records)
	}
	// HTMLは確認段階では変更せず、同じ値を適用・再送する。
	htmlPath := strings.TrimPrefix(path, "/api/v1")
	res, body = client.request("GET", htmlPath, "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "スレッドの状態変更") {
		t.Fatal(res.StatusCode, body)
	}
	fields := url.Values{"csrf": {pageFields(body).Get("csrf")}, "revision": {pageFields(body).Get("revision")}, "request_id": {pageFields(body).Get("request_id")}, "step": {"confirm"}, "kind": {"archive"}, "target": {""}, "commands": {"[]"}, "policy_version": {"1"}, "slip_mode": {"none"}, "require_public_ip": {"false"}, "require_slip_hash": {"false"}, "id_mode": {"required"}, "require_id": {"true"}, "post_limit": {"1000"}, "dat_limit": {"524288"}}
	res, body = client.request("POST", htmlPath, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 || !strings.Contains(body, "変更内容の確認") {
		t.Fatal(res.StatusCode, body)
	}
	records, _ = repo.posting[board.ID].threadActions()
	if len(records) != 0 {
		t.Fatal("confirmed action wrote", records)
	}
	fields.Set("step", "apply")
	res, body = client.request("POST", htmlPath, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 || !strings.Contains(body, "反映済み") {
		t.Fatal(res.StatusCode, body)
	}
	records, _ = repo.posting[board.ID].threadActions()
	raw, _ = json.Marshal(records[0])
	if err := validateThreadAction(records[0].ID.String(), nil, raw); err == nil {
		t.Fatal("applied accepted as initial")
	}
	prior := records[0]
	prior.Phase = "intent"
	before, _ := json.Marshal(prior)
	if err := validateThreadAction(prior.ID.String(), before, raw); err != nil {
		t.Fatal(err)
	}
	tampered := records[0]
	tampered.Thread = domain.U64(created.Key + 1)
	raw, _ = json.Marshal(tampered)
	if err := validateThreadAction(prior.ID.String(), before, raw); err == nil {
		t.Fatal("ownership change accepted")
	}
	var decoded ThreadActionRecord
	if strictjson.Decode(before, &decoded) != nil {
		t.Fatal("record decode")
	}
}

func TestThreadActionExpiryAndBackup(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(context.Background(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	client.login(adminTestSecret)
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer func() { form.Close() }()
	created, err := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"test"}, "MESSAGE": {"body"}, "oimo_request_id": {"thread-expiry-create-001"}})
	if err != nil || !created.Accepted {
		t.Fatal(err, created)
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/actions", board.ID, created.Key)
	res, _ := client.request("GET", path, "", nil)
	headers := http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"thread-expiry-request-001"}}
	b := repo.posting[board.ID]
	b.deletionCheckpoint = func(stage string) error {
		if stage == "action:intent" {
			return errors.New("interrupt")
		}
		return nil
	}
	res, _ = client.request("POST", path, `{"kind":"stop","target":"","policy":null}`, headers)
	if res.StatusCode != 503 {
		t.Fatal(res.StatusCode)
	}
	_, err = b.worker.Submit(context.Background(), func() (any, error) {
		b.deletionCheckpoint = nil
		records, err := b.threadActions()
		if err != nil {
			return nil, err
		}
		v := records[0]
		b.clock = func() time.Time { return time.Unix(0, int64(v.Expires)) }
		b.stopped = false
		saved, err := b.resumeThreadAction(v)
		if err != nil {
			return nil, err
		}
		if saved.Phase != "expired" || b.threads[created.Key].AdministrativeApplied(v.Operation, v.Expected+1, mustActionFrame(t, v)) {
			return nil, errors.New("expired intent applied")
		}
		// 期限台帳も確定させ、同じ実行内での時計逆行に公開が復活しないことを確認する。
		_, err = b.scanExpiry(true)
		b.clock = time.Now
		if b.threads[created.Key].Snapshot(domain.Time(time.Now().UnixNano())) != nil {
			return nil, errors.New("expired public restored")
		}
		return nil, err
	})
	if err != nil {
		t.Fatal(err)
	}
	res, expiryBody := client.request("GET", path, "", nil)
	var view struct {
		Data threadActionView `json:"data"`
	}
	if res.StatusCode != 200 || json.Unmarshal([]byte(expiryBody), &view) != nil || len(view.Data.Actions) != 1 || view.Data.Actions[0].Phase != "expired" || view.Data.Actions[0].Revision != view.Data.Revision {
		t.Fatal("expired action revision", res.StatusCode, expiryBody)
	}
	form.Close()
	client.server.Close()
	repo.Close()
	// 保持期限より前への逆行でこの期限終了記録を公開しない。
	opened, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err == nil {
		opened.Close()
		t.Fatal("expired action accepted after clock regression")
	}
	// 通常の確定済み管理変更を独立候補へ捕捉し、鍵束を使って隔離再生する。
	cfg, repo = adminFixture(t)
	board, err = repo.CreateBoard(context.Background(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	client = newAdminClient(t, repo)
	client.login(adminTestSecret)
	form = formServer(t, repo, siteID(repo.site.State()), board.ID)
	created, err = sendForm(form, url.Values{"bbs": {"news"}, "subject": {"backup"}, "MESSAGE": {"body"}, "oimo_request_id": {"action-backup-create-001"}})
	if err != nil || !created.Accepted {
		t.Fatal(err, created)
	}
	path = fmt.Sprintf("/api/v1/boards/%s/threads/%d/actions", board.ID, created.Key)
	res, _ = client.request("GET", path, "", nil)
	headers = http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"action-backup-request-001"}}
	res, body := client.request("POST", path, `{"kind":"archive","target":"","policy":null}`, headers)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	form.Close()
	client.server.Close()
	repo.Close()
	parent := t.TempDir()
	if err = os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	backup, keys, work := filepath.Join(parent, "body"), filepath.Join(parent, "keys"), filepath.Join(parent, "work")
	if _, err = CaptureOfflineBackup(context.Background(), cfg, backup); err != nil {
		t.Fatal(err)
	}
	if _, err = ExportBackupKeys(context.Background(), cfg, backup, keys); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyBackupReplay(context.Background(), backup, keys, work)
	if err != nil || !report.Replayed || report.RestoreReady {
		t.Fatal(report, err)
	}
	// 先行intent全体の喪失を未知管理操作として拒否する。
	ledger := filepath.Join(cfg.DataDir, "expiry", board.ID.String(), fmt.Sprint(created.Key))
	if err = os.Rename(ledger, filepath.Join(t.TempDir(), "missing-ledger")); err != nil {
		t.Fatal(err)
	}
	opened, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err == nil {
		opened.Close()
		t.Fatal("lost action ledger accepted")
	}
}

func mustActionFrame(t *testing.T, v ThreadActionRecord) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.Strict().DecodeString(v.Frame)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestThreadActionRoleAndScope(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(context.Background(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	outside, err := repo.CreateBoard(context.Background(), "outside", "別板")
	if err != nil {
		t.Fatal(err)
	}
	owner := newAdminClient(t, repo)
	defer owner.server.Close()
	owner.login(adminTestSecret)
	owner.reauth(adminTestSecret)
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	created, err := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"roles"}, "MESSAGE": {"body"}, "oimo_request_id": {"action-roles-create-001"}})
	if err != nil || !created.Accepted {
		t.Fatal(err, created)
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/actions", board.ID, created.Key)
	for _, role := range []string{"moderator"} {
		list, _ := owner.request("GET", "/api/v1/administrators", "", nil)
		input := accountInput{Login: "action." + role, Display: "担当者", Password: "private-thread-action-password", Access: AdministratorAccess{Role: role, Boards: []domain.ID{board.ID}, Permissions: []string{}, Enabled: true}}
		res, account, body := owner.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
		c := newAdminClient(t, repo)
		defer c.server.Close()
		_, body = c.request("GET", "/login", "", nil)
		fields := pageFields(body)
		fields.Set("login", input.Login)
		fields.Set("password", input.Password)
		res, _ = c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 303 {
			t.Fatal("login", res.StatusCode)
		}
		res, _ = c.request("GET", fmt.Sprintf("/api/v1/boards/%s/threads/1/actions", outside.ID), "", nil)
		if res.StatusCode != 403 {
			t.Fatal("outside existence", res.StatusCode)
		}
		res, body = c.request("GET", path, "", nil)
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
		headers := http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"thread-role-request-0001"}}
		res, _ = c.request("POST", path, `{"kind":"archive","target":"","policy":null}`, headers)
		if res.StatusCode != 403 {
			t.Fatal("archive role", res.StatusCode)
		}
		res, body = c.request("POST", path, `{"kind":"stop","target":"","policy":null}`, headers)
		expected := 403
		if role == "moderator" {
			expected = 200
		}
		if res.StatusCode != expected {
			t.Fatal("stop role", res.StatusCode, body)
		}
		res, body = c.request("GET", path, "", nil)
		var view struct {
			Data threadActionView `json:"data"`
		}
		if res.StatusCode != 200 || json.Unmarshal([]byte(body), &view) != nil || len(view.Data.Actions) != 0 {
			t.Fatal("moderator operation history leaked", res.StatusCode, body)
		}
		accountPath := "/api/v1/administrators/" + account.ID.String()
		res, _ = owner.request("GET", accountPath, "", nil)
		input.Password = ""
		input.Access.Enabled = false
		res, _, body = owner.accountChange("PATCH", accountPath, input, res.Header.Get("ETag"), res.Header.Get("X-CSRF-Token"), domain.NewID().String())
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
		res, _ = c.request("GET", path, "", nil)
		if res.StatusCode != 401 {
			t.Fatal("revoked session", res.StatusCode)
		}
	}
}

func TestThreadActionsFixture(t *testing.T) {
	raw, err := os.ReadFile("../../docs/design/fixtures/thread-actions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema string `json:"schema"`
		Cases  []struct {
			Name  string            `json:"name"`
			Value AdminThreadAction `json:"value"`
			Valid bool              `json:"valid"`
		} `json:"cases"`
	}
	if strictjson.Decode(raw, &fixture) != nil || fixture.Schema != "thread-actions-v1" {
		t.Fatal("fixture schema")
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if valid := tc.Value.validate() == nil; valid != tc.Valid {
				t.Fatal("validator", valid)
			}
		})
	}
}
