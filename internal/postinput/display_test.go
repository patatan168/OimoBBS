// SLIP全方式、明示IP、匿名表示の弱化拒否と入力命令の秘密境界を検査する。
package postinput

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"strings"
	"testing"
	"time"
)

func TestSlipDisplayModes(t *testing.T) {
	for _, mode := range []string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"} {
		t.Run(mode, func(t *testing.T) {
			c := buildContext()
			c.SlipNetKey = domain.Hash{3}
			c.SlipUAKey = domain.Hash{4}
			c.UserAgent = "Monazilla/1.00"
			c.Network = identity.NetworkClass{Kind: "mvno", Label: "ﾌﾞｰｲﾓ", Suffix: "M"}
			c.Policy.SlipMode = mode
			out, dat := applyInput(t, nil, map[string]string{"subject": "表示", "MESSAGE": "本文"}, c)
			p := out.Posts[0]
			if mode == "none" {
				if p.Identity.Suffix != "" {
					t.Fatal(p.Identity)
				}
			} else if mode == "checked" {
				if p.Identity.Suffix != "0" {
					t.Fatal(p.Identity)
				}
			} else if p.Identity.Suffix != "M" {
				t.Fatal(p.Identity)
			}
			if strings.HasPrefix(mode, "vvv") {
				if !strings.Contains(dat, "</b>(ﾌﾞｰｲﾓ") || !strings.Contains(dat, "<b><>") {
					t.Fatal(dat)
				}
			} else if p.Identity.Slip != "" {
				t.Fatal(dat)
			}
			if HasPublicIP(c.Policy) != strings.Contains(dat, "[192.0.2.1]") {
				t.Fatal("IP visibility", dat)
			}
			if HasSlipHash(c.Policy) && !strings.Contains(p.Identity.Slip, "-") {
				t.Fatal(p.Identity)
			}
		})
	}
	c := buildContext()
	c.Policy.RequirePublicIP = true
	out, dat := applyInput(t, nil, map[string]string{"subject": "IP", "MESSAGE": "本文"}, c)
	if out.Posts[0].Identity.PublicIP != "192.0.2.1" || !strings.Contains(dat, "[192.0.2.1]") {
		t.Fatal(dat)
	}
}
func TestDisplayControls(t *testing.T) {
	fields := map[string]string{"FROM": "名前 !slip:vvvvv#secret-trip-key", "subject": "題", "MESSAGE": "本文"}
	in, e := Prepare(fields, true, domain.Hash{1})
	if e != nil || in.Name != "名前" || in.Controls.Slip != "vvvvv" || in.Controls.Thread {
		t.Fatal(in, e)
	}
	c := buildContext()
	c.AllowStrengthen = true
	c.SlipNetKey = domain.Hash{2}
	c.SlipUAKey = domain.Hash{3}
	old, dat := applyInput(t, nil, map[string]string{"subject": "題", "MESSAGE": "!extend:checked:vvvvv::\n本文"}, c)
	if old.Policy.SlipMode != "vvvvv" || old.Posts[0].Body != "本文" || !strings.Contains(dat, "</b>(ﾜｯﾁｮｲ ") {
		t.Fatal(old, dat)
	}
	c.Now = c.Now.Add(time.Second)
	next, dat := applyInput(t, old, map[string]string{"MESSAGE": "返信"}, c)
	if next.Posts[1].Identity.Slip == "" || !strings.Contains(dat, "</b>(ﾜｯﾁｮｲ ") {
		t.Fatal(dat)
	}
	p := old.Policy
	for _, v := range []Controls{{Slip: "none"}, {Slip: "feature"}, {ID: "off"}} {
		if _, e := DisplayPolicy(p, &v, true); e == nil {
			t.Fatal("weakened", v)
		}
	}
	if _, e := DisplayPolicy(p, &Controls{Slip: "vvvvvv"}, false); e == nil {
		t.Fatal("disallowed strength")
	}
	fields["FROM"] = "&#33;slip:vvvvv"
	in, e = Prepare(fields, true, domain.Hash{1})
	if e != nil || in.Controls != nil || in.Name != "!slip:vvvvv" {
		t.Fatal("reference activated", in, e)
	}
	for _, name := range []string{"!slip:vvvvv !slip:verbose", "!id:on !id:off", "!slip:bad"} {
		fields["FROM"] = name
		if _, e = Prepare(fields, true, domain.Hash{1}); e == nil {
			t.Fatal("bad commands", name)
		}
	}
}

func TestExtendTemplateAndDedupBinding(t *testing.T) {
	fields := map[string]string{"subject": "題", "MESSAGE": "!extend:checked:vvvvv::\n!extend:checked:vvvvv::\n本文"}
	in, e := Prepare(fields, true, domain.Hash{1})
	if e != nil || in.Body != "!extend:checked:vvvvv::\n本文" || in.Controls == nil || !in.Controls.Thread {
		t.Fatal(in, e)
	}
	d := in.Dedup(domain.Hash{1}, domain.ID{1}, 0, []byte("192.0.2.1"), 1)
	copyInput := in
	control := *in.Controls
	control.Slip = "vvvvvv"
	copyInput.Controls = &control
	changed := copyInput.Dedup(domain.Hash{1}, domain.ID{1}, 0, []byte("192.0.2.1"), 1)
	if d.Request == changed.Request {
		t.Fatal("display commands not bound to request")
	}
	fields["MESSAGE"] = "!extend:checked:vvvvv::\n!extend:checked:broken::\n本文"
	if _, e = Prepare(fields, true, domain.Hash{1}); e == nil {
		t.Fatal("invalid later extend accepted")
	}
	fields = map[string]string{"MESSAGE": "!extend:checked:vvvvv::\n返信"}
	reply, e := Prepare(fields, false, domain.Hash{1})
	if e != nil || reply.Controls != nil || reply.Body != fields["MESSAGE"] {
		t.Fatal(reply, e)
	}
}

// DNS特殊表示は固定回線でも保ち、none/checkedの公開仕様は維持する。
func TestDNSDiagnosticDisplayModes(t *testing.T) {
	for _, tc := range []struct{ label, suffix string }{{"ｱﾝﾀﾀﾞﾚ", "h"}, {"JP", "H"}} {
		for _, mode := range []string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"} {
			c := buildContext()
			c.SlipNetKey = domain.Hash{3}
			c.SlipUAKey = domain.Hash{4}
			c.UserAgent = "Monazilla/1.00"
			c.Network = identity.NetworkClass{Kind: "fixed", Label: tc.label, Suffix: tc.suffix}
			c.Policy.SlipMode = mode
			out, dat := applyInput(t, nil, map[string]string{"subject": "DNS表示", "MESSAGE": "本文"}, c)
			post := out.Posts[0]
			expected := tc.suffix
			if mode == "none" {
				expected = ""
			}
			if mode == "checked" {
				expected = "0"
			}
			if post.Identity.Suffix != expected {
				t.Fatal(mode, post.Identity)
			}
			if strings.HasPrefix(mode, "vvv") && (!strings.Contains(post.Identity.Slip, "("+tc.label) || strings.Contains(dat, "(ﾜｯﾁｮｲ")) {
				t.Fatal(mode, post.Identity, dat)
			}
		}
	}
}
