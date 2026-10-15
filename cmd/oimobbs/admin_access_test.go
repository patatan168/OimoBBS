// アクセス設定CLIの未知UUID・秘密入力の混同を拒否し、明示する担当集合を保つ。
package main

import (
	"bytes"
	"oimobbs/internal/domain"
	"strings"
	"testing"
)

func TestAdministratorAccessArguments(t *testing.T) {
	id := domain.NewID()
	v, e := parseAdministratorAccess("moderator", id.String(), "evidence.manage", true)
	if e != nil || len(v.Boards) != 1 || v.Boards[0] != id || len(v.Permissions) != 1 || !v.Enabled {
		t.Fatal(v, e)
	}
	if _, e = parseAdministratorAccess("moderator", "not-a-uuid", "", true); e == nil {
		t.Fatal("invalid board UUID")
	}
	for _, args := range [][]string{
		{"init", "--login", "owner", "--password-stdin", "--role", "moderator"},
		{"set-access", "--login", "owner", "--role", "moderator", "--password-stdin"},
		{"reset-password", "--login", "owner", "--password-stdin", "--extra-permissions", "evidence.manage"},
	} {
		var output bytes.Buffer
		if e := runAdmin(args, strings.NewReader("private-password-never-printed"), &output, &output); e == nil {
			t.Fatal("ambiguous flags accepted", args)
		}
		if strings.Contains(output.String(), "private-password") {
			t.Fatal("password printed")
		}
	}
}
