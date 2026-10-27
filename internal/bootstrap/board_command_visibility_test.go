// 板の既定に応じた表示候補と、非表示の許可を保存時に失わないことを検証する。
package bootstrap

import (
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestBoardCommandVisibility(t *testing.T) {
	for _, tc := range []struct {
		id, slip, command string
		visible           bool
	}{
		{"required", "vvvvv", "!slip:vvvv", false},
		{"required", "vvvvv", "!slip:vvvvv", true},
		{"required", "vvvvv", "!slip:vvvvvv", true},
		{"required", "vvvvv", "!extend:none:vvvvvv::", false},
		{"required", "vvvvv", "!extend:checked:verbose::", false},
		{"required", "vvvvv", "!extend:checked:default::", true},
		{"optional", "none", "!extend:none:vvvvv::", true},
		{"hidden", "none", "!id:on", true},
		{"optional", "vvvvvv", "!slip:vvvvv", false},
	} {
		p := adminBoardsPage{Values: url.Values{"id_mode": {tc.id}, "slip_mode": {tc.slip}, "require_public_ip": {"false"}}}
		if got := p.DisplayCommandAvailable(tc.command); got != tc.visible {
			t.Fatal(tc, got)
		}
	}
}

func TestBoardCommandVisibilityHTML(t *testing.T) {
	option := regexp.MustCompile(`<label class="check-option" data-command-option([^>]*)><input type="checkbox" name="display_commands" value="([^"]+)"([^>]*)>`)
	for _, tc := range []struct {
		id, slip, ip string
		shown        int
	}{
		{"required", "none", "false", 27}, {"optional", "none", "false", 36},
		{"required", "vvvvv", "false", 9}, {"optional", "vvvvv", "false", 12},
		{"required", "vvvvvv", "false", 6}, {"optional", "vvvvvv", "false", 8},
		{"required", "none", "true", 12}, {"required", "vvvvv", "true", 6},
	} {
		p := adminBoardsPage{Editing: true, Values: url.Values{"id_mode": {tc.id}, "slip_mode": {tc.slip}, "require_public_ip": {tc.ip}, "allow_thread_strengthen": {"true"}, "display_commands": {"null"}}}
		w := httptest.NewRecorder()
		writeAdminBoards(w, 200, p)
		if w.Code != 200 {
			t.Fatal("template", w.Code)
		}
		options := option.FindAllStringSubmatch(w.Body.String(), -1)
		if len(options) != 36 {
			t.Fatal("lost permission fields", len(options))
		}
		shown := 0
		fields := url.Values{"display_command_selection": {"1"}}
		for _, o := range options {
			if !strings.Contains(o[1], "hidden") {
				shown++
			}
			if !strings.Contains(o[3], "checked") {
				t.Fatal("hidden permission lost", o[2])
			}
			fields.Add("display_commands", o[2])
		}
		if shown != tc.shown {
			t.Fatal(tc, shown)
		}
		if normalizeDisplayCommands(fields) != nil {
			t.Fatal("permission submission")
		}
	}
}
