// 板別コマンド設定のHTML保存・投稿への適用・説明表示・再起動復旧を検証する。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestBoardDisplayCommandSetting(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	on, err := repo.CreateBoard(t.Context(), "commands_on", "反映する板")
	if err != nil {
		t.Fatal(err)
	}
	off, err := repo.CreateBoard(t.Context(), "commands_off", "反映しない板")
	if err != nil {
		t.Fatal(err)
	}
	admin := newAdminClient(t, repo)
	defer func() { admin.server.Close() }()
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	for _, tc := range []struct {
		board   BoardInfo
		allowed bool
	}{{on, true}, {off, false}} {
		path := "/boards/" + tc.board.ID.String() + "/settings"
		res, page := admin.request("GET", path, "", nil)
		if res.StatusCode != 200 {
			t.Fatal("settings", res.StatusCode)
		}
		for _, label := range []string{"ワッチョイコマンドの個別ON/OFF", "コマンド付き投稿を拒否", "回線名と週ごとの識別子を表示（ワッチョイ）", "!extend:default:vvvvv::", "!extend:checked:vvvvvv::", "!slip:vvvvv", "!id:on"} {
			if !strings.Contains(page, label) {
				t.Fatal("missing meaning/command", label)
			}
		}
		_, current := admin.board(tc.board.ID.String())
		fields := adminBoardFields(current.Settings)
		hidden := pageFields(page)
		for _, key := range []string{"csrf", "revision", "request_id"} {
			fields.Set(key, hidden.Get(key))
		}
		fields.Set("allow_thread_strengthen", fmt.Sprint(tc.allowed))
		res, _ = admin.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 303 {
			t.Fatal("HTML save", res.StatusCode)
		}
		_, current = admin.board(tc.board.ID.String())
		if current.Settings.identitySettings().AllowStrengthen != tc.allowed {
			t.Fatal("saved flag")
		}
		form := formServer(t, repo, siteID(repo.site.State()), tc.board.ID)
		for i, command := range []string{"!extend:checked:vvvvv::", "!slip:vvvvv"} {
			fields := url.Values{"bbs": {tc.board.Key}, "subject": {"表示変更"}, "MESSAGE": {"本文"}, "oimo_request_id": {fmt.Sprintf("board-command-%s-%d", tc.board.Key, i)}}
			if i == 0 {
				fields.Set("MESSAGE", command+"\n本文")
			} else {
				fields.Set("FROM", command)
			}
			result, e := sendForm(form, fields)
			if e != nil || result.Accepted != tc.allowed || !tc.allowed && result.Confirmation != nil {
				t.Fatal("posting switch", tc.board.Key, command, e)
			}
			if tc.allowed && i == 0 {
				b := repo.posting[tc.board.ID]
				policy, e := b.worker.Submit(t.Context(), func() (any, error) {
					p, ok := b.threads[result.Key].PostingPolicy(domain.Time(b.clock().UnixNano()))
					if !ok {
						return nil, fmt.Errorf("missing thread policy")
					}
					return p, nil
				})
				if e != nil || policy.(domain.Policy).SlipMode != "vvvvv" {
					t.Fatal("extend not applied", e)
				}
			}
		}
		plain, e := sendForm(form, url.Values{"bbs": {tc.board.Key}, "subject": {"通常"}, "MESSAGE": {"本文"}, "oimo_request_id": {"plain-" + tc.board.Key}})
		form.Close()
		if e != nil || !plain.Accepted {
			t.Fatal("ordinary posting", tc.board.Key, e)
		}
	}
	admin.server.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen", err)
	}
	admin = newAdminClient(t, repo)
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("recovered login")
	}
	for _, tc := range []struct {
		board   BoardInfo
		allowed bool
	}{{on, true}, {off, false}} {
		_, saved := admin.board(tc.board.ID.String())
		if saved.Settings.identitySettings().AllowStrengthen != tc.allowed {
			t.Fatal("recovered flag", tc.board.Key)
		}
	}
}
