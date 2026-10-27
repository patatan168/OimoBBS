// 管理HTMLの個別許可保存から投稿・確認・再起動まで、板ごとの適用を検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/strictjson"
	"reflect"
	"strings"
	"testing"

	"oimobbs/internal/postcapture"
)

func TestBoardIndividualDisplayCommands(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	a, e := repo.CreateBoard(t.Context(), "individual", "個別設定")
	if e != nil {
		t.Fatal(e)
	}
	b, e := repo.CreateBoard(t.Context(), "alloff", "全OFF")
	if e != nil {
		t.Fatal(e)
	}
	admin := newAdminClient(t, repo)
	defer func() { admin.server.Close() }()
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	allowed := []string{"!extend:checked:vvvvv::", "!id:on", "!slip:vvvvv"}
	for _, board := range []BoardInfo{a, b} {
		path := "/boards/" + board.ID.String() + "/settings"
		res, page := admin.request("GET", path, "", nil)
		if res.StatusCode != 200 || strings.Count(page, `type="checkbox" name="display_commands"`) != 36 {
			t.Fatal("individual controls", res.StatusCode)
		}
		_, saved := admin.board(board.ID.String())
		fields := adminBoardFields(saved.Settings)
		hidden := pageFields(page)
		for _, key := range []string{"csrf", "revision", "request_id"} {
			fields.Set(key, hidden.Get(key))
		}
		fields.Set("display_command_selection", "1")
		fields.Del("display_commands")
		if board.ID == a.ID {
			fields["display_commands"] = allowed
		}
		res, _ = admin.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 303 {
			t.Fatal("save", res.StatusCode)
		}
		_, saved = admin.board(board.ID.String())
		names := saved.Settings.identitySettings().DisplayCommands
		if names == nil || board.ID == a.ID && !reflect.DeepEqual(*names, allowed) || board.ID == b.ID && len(*names) != 0 {
			t.Fatal("saved list", names)
		}
		res, page = admin.request("GET", path, "", nil)
		if res.StatusCode != 200 {
			t.Fatal("reload")
		}
		for _, command := range []string{"!slip:vvvvv", "!slip:vvvvvv", "!extend:checked:vvvvv::"} {
			checked := strings.Contains(page, `value="`+command+`" checked`)
			want := board.ID == a.ID && command != "!slip:vvvvvv"
			if checked != want {
				t.Fatal("checkbox state", command, checked)
			}
		}
		// 旧APIが新項目を省略して他の設定を変更しても、個別許可を解除しない。
		response, current := admin.board(board.ID.String())
		edit := current.Settings
		edit.Identity.DisplayCommands = nil
		body, err := json.Marshal(edit)
		if err != nil {
			t.Fatal(err)
		}
		response, _ = admin.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(body), http.Header{
			"Content-Type": {"application/json"}, "If-Match": {response.Header.Get("ETag")},
			"X-CSRF-Token": {response.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"individual-legacy-" + board.Key},
		})
		if response.StatusCode != 200 {
			t.Fatal("legacy API save", response.StatusCode)
		}
		_, current = admin.board(board.ID.String())
		if !reflect.DeepEqual(current.Settings.identitySettings().DisplayCommands, names) {
			t.Fatal("legacy API cleared permissions")
		}
		form := formServer(t, repo, siteID(repo.site.State()), board.ID)
		for i, tc := range []struct {
			name, body string
			ok         bool
		}{
			{"", "本文", true}, {"!slip:vvvvv", "本文", board.ID == a.ID},
			{"!slip:vvvvvv", "本文", false}, {"!id:on !slip:vvvvv", "本文", board.ID == a.ID},
			{"!id:on !slip:vvvvvv", "本文", false}, {"", "!extend:checked:vvvvv::\n本文", board.ID == a.ID},
			{"", "!extend:checked:vvvvvv::\n本文", false}, {"", "!extend:default:vvvvv::\n本文", false},
			{"", "!extend::vvvvv::\n本文", false},
		} {
			result, err := sendForm(form, url.Values{"bbs": {board.Key}, "subject": {"コマンド検証"}, "FROM": {tc.name}, "MESSAGE": {tc.body}, "oimo_request_id": {fmt.Sprintf("individual-%s-%d", board.Key, i)}})
			if err != nil || result.Accepted != tc.ok || !tc.ok && result.Confirmation != nil {
				t.Fatal("command admission", i, board.Key, result, err)
			}
		}
		// 返信も現在の板設定で検査し、!slipの適用と!extend許可を独立させる。
		created, err := sendForm(form, url.Values{"bbs": {board.Key}, "subject": {"返信検証"}, "MESSAGE": {"本文"}, "oimo_request_id": {"individual-reply-create-" + board.Key}})
		if err != nil || !created.Accepted {
			t.Fatal("create", err)
		}
		for i, name := range []string{"!slip:vvvvv", "!slip:vvvvvv"} {
			result, err := sendForm(form, url.Values{"bbs": {board.Key}, "key": {fmt.Sprint(created.Key)}, "FROM": {name}, "MESSAGE": {"返信"}, "oimo_request_id": {fmt.Sprintf("individual-reply-%s-%d", board.Key, i)}})
			if err != nil || result.Accepted != (board.ID == a.ID && i == 0) {
				t.Fatal("reply", err, result)
			}
		}
		form.Close()
	}
	admin.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("recovery", e)
	}
	admin = newAdminClient(t, repo)
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("recovered login")
	}
	for _, board := range []BoardInfo{a, b} {
		_, saved := admin.board(board.ID.String())
		names := saved.Settings.identitySettings().DisplayCommands
		if names == nil || board.ID == a.ID && !reflect.DeepEqual(*names, allowed) || board.ID == b.ID && len(*names) != 0 {
			t.Fatal("recovered commands")
		}
	}
}

func TestDisplayCommandFormValidation(t *testing.T) {
	for _, v := range []url.Values{
		{"display_command_selection": {"1"}, "display_commands": {"!slip:unknown"}},
		{"display_command_selection": {"1"}, "display_commands": {"!slip:vvvvv", "!slip:vvvvv"}},
		{"display_command_selection": {"1", "1"}},
	} {
		if normalizeDisplayCommands(v) == nil {
			t.Fatal("invalid form accepted")
		}
	}
}

func TestIndividualCommandsStorageCompatibility(t *testing.T) {
	old := defaultBoardSettings().Identity
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "display_commands") {
		t.Fatal("legacy JSON changed")
	}
	var restored boardIdentity
	if err = strictjson.Decode(raw, &restored); err != nil || !reflect.DeepEqual(old, restored) {
		t.Fatal("legacy identity", err)
	}
	empty := []string{}
	restored.DisplayCommands = &empty
	raw, err = json.Marshal(restored)
	if err != nil || !strings.Contains(string(raw), `"display_commands":[]`) {
		t.Fatal("empty permission omitted", err)
	}
	if err = strictjson.Decode(raw, &restored); err != nil || restored.DisplayCommands == nil || len(*restored.DisplayCommands) != 0 {
		t.Fatal("empty permission recovery", err)
	}
	board := boardValue{Settings: defaultBoardSettings()}
	board.Settings.Identity = restored
	if validateIdentityReader(siteState{MinimumReader: 73}, board) == nil {
		t.Fatal("old reader permitted")
	}
	if err = validateIdentityReader(siteState{MinimumReader: 74}, board); err != nil {
		t.Fatal("reader74", err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"id_mode":"required",`, "", 1),
		strings.Replace(string(raw), `"id_mode":"required"`, `"id_mode":"required","id_mode":"required"`, 1),
		strings.Replace(string(raw), `"display_commands":[]`, `"display_commands":[],"unknown":true`, 1),
	} {
		if strictjson.Decode([]byte(bad), &restored) == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	if !old.extendCommandEnabled() || restored.extendCommandEnabled() {
		t.Fatal("SETTING.TXT command flag")
	}
}
