// 同一表示名の固定プロバイダとCookie主体がDATの別区画へ反映されることを検査する。
package postinput

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"strings"
	"testing"
)

func TestSlipV2FixedProviderDisplay(t *testing.T) {
	c := buildContext()
	c.AnonymousID = domain.ID{9}
	c.SlipNetKey, c.SlipUAKey = domain.Hash{3}, domain.Hash{4}
	c.Policy.SlipMode = "vvvvv"
	c.Network = identity.NetworkClass{Kind: "fixed", Label: "OCN", Suffix: "0", Provider: "ocn"}
	first, dat := applyInput(t, nil, map[string]string{"subject": "題", "MESSAGE": "本文"}, c)
	if !strings.Contains(dat, "</b>(ﾜｯﾁｮｲ ") || strings.Contains(dat, "(OCN ") {
		t.Fatal(dat)
	}
	c.Network.Provider, c.Network.Label = "iij", "IIJ"
	second, _ := applyInput(t, nil, map[string]string{"subject": "題", "MESSAGE": "本文"}, c)
	a, b := strings.Fields(first.Posts[0].Identity.Slip)[1], strings.Fields(second.Posts[0].Identity.Slip)[1]
	if a[:2] != b[:2] || a[2:4] == b[2:4] || a[5:] != b[5:] {
		t.Fatal(a, b)
	}
	c.AnonymousID = domain.ID{}
	in, _ := Prepare(map[string]string{"subject": "題", "MESSAGE": "本文"}, true, domain.Hash{3})
	if _, err := Build(nil, in, c); err == nil {
		t.Fatal("hash without verified ID accepted")
	}
}
