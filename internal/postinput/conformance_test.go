// 5ch公開資料の期待値を手で固定し、設定名からDATまでの意味の逆転を防ぐ。
package postinput

import (
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"strings"
	"testing"
)

// 公開資料: https://info.5ch.io/index.php/BBS_SLIP （2026-10-04照合）。
func Test5chIdentityDisplayContract(t *testing.T) {
	modes := []struct {
		mode, suffix   string
		name, hash, ip bool
	}{
		{"none", "", false, false, false}, {"checked", "0", false, false, false}, {"feature", "S", false, false, false}, {"verbose", "d", false, false, false},
		{"vvv", "d", true, false, false}, {"vvvv", "d", true, false, true}, {"vvvvv", "d", true, true, false}, {"vvvvvv", "d", true, true, true},
	}
	for _, tc := range modes {
		for _, id := range []string{"required", "optional", "hidden"} {
			for _, mail := range []string{"", "sage"} {
				t.Run(tc.mode+"/"+id+"/"+mail, func(t *testing.T) {
					c := buildContext()
					c.Policy.SlipMode = tc.mode
					c.Policy.IDMode = id
					c.SlipNetKey = domain.Hash{3}
					c.SlipUAKey = domain.Hash{4}
					c.Network = identity.NetworkClass{Kind: "mobile", Label: "ｽﾌﾟｯｯ", Suffix: "d"}
					out, dat := applyInput(t, nil, map[string]string{"subject": "題", "MESSAGE": "本文", "mail": mail}, c)
					p := out.Posts[0]
					if p.Identity.Suffix != tc.suffix || (p.Identity.Slip != "") != tc.name || strings.Contains(p.Identity.Slip, "-") != tc.hash || strings.Contains(dat, "[192.0.2.1]") != tc.ip {
						t.Fatal(p.Identity, dat)
					}
					switch {
					case id == "required" || id == "optional" && mail == "":
						if len(p.Identity.ID) != 8 || !strings.Contains(dat, "ID:"+p.Identity.ID+tc.suffix) {
							t.Fatal(p.Identity, dat)
						}
					case id == "optional":
						if p.Identity.ID != "???" || !strings.Contains(dat, "ID:???"+tc.suffix) {
							t.Fatal(p.Identity, dat)
						}
					default:
						if p.Identity.ID != "" || strings.Contains(dat, "ID:") {
							t.Fatal(p.Identity, dat)
						}
						if tc.suffix != "" && !strings.Contains(dat, " "+tc.suffix+"<>") {
							t.Fatal("hidden ID suffix lost", dat)
						}
					}
				})
			}
		}
	}
}

func Test5chCheckedTerminalSuffix(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{{"O", "O"}, {"Q", "Q"}, {"o", "o"}, {"d", "0"}, {"M", "0"}, {"F", "0"}} {
		c := buildContext()
		c.Policy.SlipMode = "checked"
		c.Network = identity.NetworkClass{Label: "端末", Suffix: tc.raw}
		out, _ := applyInput(t, nil, map[string]string{"subject": "題", "MESSAGE": "本文"}, c)
		if out.Posts[0].Identity.Suffix != tc.want {
			t.Fatal(tc, out.Posts[0].Identity)
		}
	}
}

func Test5chDisplayCommandContract(t *testing.T) {
	for _, body := range []string{"!extend:default:default::\n本文", "!extend:checked:default::\n本文", "!extend:default:vvvvv::\n本文"} {
		in, e := Prepare(map[string]string{"subject": "題", "MESSAGE": body}, true, domain.Hash{1})
		if e != nil || in.Body != "本文" || in.Controls == nil {
			t.Fatal(in, e)
		}
		p := buildContext().Policy
		p.SlipMode = "feature"
		p.IDMode = "optional"
		next, e := DisplayPolicy(p, in.Controls, true)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(body, ":default:default:") && (next.IDMode != "optional" || next.SlipMode != "feature") {
			t.Fatal("defaults not inherited", next)
		}
	}
	for _, cmd := range []string{"!id:none", "!id:ignore"} {
		if _, e := Prepare(map[string]string{"FROM": cmd, "MESSAGE": "本文"}, false, domain.Hash{1}); !errors.Is(e, ErrUnsupported) {
			t.Fatal(cmd, e)
		}
	}
	if _, e := Prepare(map[string]string{"FROM": "!id:off", "MESSAGE": "本文"}, false, domain.Hash{1}); !errors.Is(e, ErrInput) {
		t.Fatal("nonstandard off accepted", e)
	}
	p := buildContext().Policy
	p.IDMode = "hidden"
	next, e := DisplayPolicy(p, &Controls{ID: "on"}, true)
	if e != nil || next.IDMode != "required" {
		t.Fatal("normal hidden must permit ID addition", next, e)
	}
	for _, mode := range []string{"checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"} {
		p := buildContext().Policy
		p.SlipMode = mode
		if _, e := DisplayPolicy(p, &Controls{Slip: "none"}, true); e == nil {
			t.Fatal("weakened", mode)
		}
	}
	p = buildContext().Policy
	p.SlipMode = "verbose"
	if _, e := DisplayPolicy(p, &Controls{Slip: "checked"}, true); e == nil {
		t.Fatal("detail weakened")
	}
	p.SlipMode = "vvvv"
	next, e = DisplayPolicy(p, &Controls{Slip: "vvvvv"}, true)
	if e != nil || next.SlipMode != "vvvvv" || HasPublicIP(next) {
		t.Fatal("documented rank", next, e)
	}
}
