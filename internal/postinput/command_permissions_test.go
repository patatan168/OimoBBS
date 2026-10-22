// コマンドごとの許可・継承指定の別名・複数コマンドの迂回拒否を検証する。
package postinput

import (
	"oimobbs/internal/domain"
	"testing"
)

func TestIndividualDisplayCommands(t *testing.T) {
	allowed := []string{"!slip:vvvvv", "!id:on", "!extend:checked:vvvvv::"}
	p := domain.Policy{IDMode: "optional", SlipMode: "none"}
	for _, tc := range []struct {
		c  *Controls
		ok bool
	}{
		{nil, true}, {&Controls{Slip: "vvvvv"}, true}, {&Controls{Slip: "vvvvvv"}, false},
		{&Controls{ID: "on", Slip: "vvvvv"}, true}, {&Controls{ID: "on", Slip: "vvvvvv"}, false},
		{&Controls{Thread: true, ID: "on", Slip: "vvvvv"}, true},
		{&Controls{Thread: true, Slip: "vvvvv"}, false}, {&Controls{Thread: true, ID: "on", Slip: "vvvvvv"}, false},
	} {
		if e := CheckDisplayCommands(tc.c, &allowed); (e == nil) != tc.ok {
			t.Fatalf("%+v: %v", tc.c, e)
		}
	}
	empty := []string{}
	if CheckDisplayCommands(&Controls{Slip: "vvvvv"}, &empty) == nil {
		t.Fatal("empty list enabled command")
	}
	if CheckDisplayCommands(nil, &empty) != nil {
		t.Fatal("ordinary input rejected")
	}
	if CheckDisplayCommands(&Controls{Slip: "vvvvvv"}, nil) != nil {
		t.Fatal("legacy permission changed")
	}
	// 各!extendを許可しても、必須表示の弱化は引き続き拒否する。
	p.IDMode = "required"
	if _, e := DisplayPolicy(p, &Controls{Thread: true, ID: "off"}, true); e == nil {
		t.Fatal("required ID weakened")
	}
	for _, body := range []string{"!extend::vvvvv::\n本文", "!extend:default:vvvvv::\n本文"} {
		input, e := Prepare(map[string]string{"subject": "題", "MESSAGE": body}, true, domain.Hash{1})
		if e != nil {
			t.Fatal(e)
		}
		if CheckDisplayCommands(input.Controls, &allowed) == nil {
			t.Fatal("default alias bypassed disabled command")
		}
	}
	all := DisplayCommandNames()
	if len(all) != 36 || ValidateDisplayCommands(all) != nil {
		t.Fatal("supported commands", len(all))
	}
	for _, bad := range [][]string{{"!slip:unknown"}, {"!id:none"}, {"!slip:vvvvv", "!slip:vvvvv"}, {"!extend::vvvvv::"}} {
		if ValidateDisplayCommands(bad) == nil {
			t.Fatal("invalid allowlist", bad)
		}
	}
}

func TestBuildChecksCurrentDisplayCommands(t *testing.T) {
	input, err := Prepare(map[string]string{"subject": "題", "MESSAGE": "本文", "FROM": "!slip:vvvvv"}, true, domain.Hash{1})
	if err != nil {
		t.Fatal(err)
	}
	c := buildContext()
	c.AllowStrengthen = true
	c.SlipNetKey = domain.Hash{2}
	c.SlipUAKey = domain.Hash{3}
	allowed := []string{"!slip:vvvvv"}
	c.DisplayCommands = &allowed
	c.Dedup = input.Dedup(domain.Hash{3}, c.Board, 0, []byte{4, 192, 0, 2, 1}, domain.Time(c.Now.UnixNano()))
	if _, err = Build(nil, input, c); err != nil {
		t.Fatal("allowed build", err)
	}
	empty := []string{}
	c.DisplayCommands = &empty
	if _, err = Build(nil, input, c); err == nil {
		t.Fatal("latest permission not checked at commit")
	}
}
