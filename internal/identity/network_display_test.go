// 旧自動表の事業者名が公開呼称へ混入しないことと、優先分類の保持を検証する。
package identity

import (
	"net/netip"
	"testing"
)

// TestAutomaticNetworkDisplay は再取得前の旧分類表にも標準の呼称を適用する。
func TestAutomaticNetworkDisplay(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	for _, kind := range []string{"fixed", "mixed", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			row := NetworkClass{CIDR: "192.0.2.0/24", Kind: kind, Label: "BIGLOBE", Suffix: "0", Provider: "biglobe"}
			table, err := CompileNetworks([]NetworkClass{row}, 1)
			if err != nil {
				t.Fatal(err)
			}
			classifier := &NetworkClassifier{Automatic: table}
			want := row
			want.Label = "ﾜｯﾁｮｲ"
			if kind == "mixed" || kind == "unknown" {
				want.Label = "ﾃﾞｶﾁｷｭｰ"
			}
			if got := classifier.Classify(nil, ip); got != want {
				t.Fatal("legacy automatic display", got)
			}
			if stored, _ := table.Match(ip); stored != row {
				t.Fatal("stored table mutated", stored)
			}
			classifier.Overrides = table
			if got := classifier.Classify(nil, ip); got != row {
				t.Fatal("manual override changed", got)
			}
			if got := classifier.Classify([]NetworkClass{row}, ip); got != row {
				t.Fatal("board override changed", got)
			}
		})
	}
}

// TestMixedProviderDisplays は混在・不明で事業者別呼称を使い、固定回線へ漏らさないことを検査する。
func TestMixedProviderDisplays(t *testing.T) {
	for provider, label := range map[string]string{
		"ocn": "ｵｼﾏｾﾞ", "kddi": "ｱｳｱｳﾏｾﾞ", "softbank": "ﾔﾜﾗｶﾏｾﾞ",
		"iij": "ｲｲｼﾞｬﾝ", "optage": "ｵﾌﾟﾏｾﾞ", "biglobe": "ﾃﾞｶﾁｷｭｰ", "": "ﾜｯﾁｮﾏｾﾞ", "other": "ﾜｯﾁｮﾏｾﾞ",
	} {
		for _, kind := range []string{"fixed", "mixed", "unknown"} {
			row := NetworkClass{CIDR: "192.0.2.0/24", Kind: kind, Label: "OLD", Suffix: "0", Provider: provider}
			want := row
			want.Label = "ﾜｯﾁｮｲ"
			if kind == "mixed" {
				want.Label = label
			} else if kind == "unknown" {
				want.Label = label
				if provider == "" || provider == "other" {
					want.Label = "ﾜｶﾗﾝ"
				}
			}
			if got := AutomaticNetworkDisplay(row); got != want {
				t.Fatal(provider, kind, got)
			}
		}
	}
}

// TestUnknownProviderDisplays は保存済みの旧表示・分類・キーと、未登録キーの扱いを検査する。
func TestUnknownProviderDisplays(t *testing.T) {
	for provider, label := range map[string]string{"freebit": "ﾀﾀﾞﾉｶｹﾗ", "transix": "ﾄﾗﾝﾄﾗﾝ", "m247": "ﾆﾖﾅﾅ", "": "ﾜｶﾗﾝ", "unregistered": "ﾜｶﾗﾝ"} {
		row := NetworkClass{CIDR: "192.0.2.0/24", Kind: "unknown", Label: "OLD", Suffix: "0", Provider: provider}
		want := row
		want.Label = label
		if got := AutomaticNetworkDisplay(row); got != want {
			t.Fatal(provider, got)
		}
		row.Kind = "fixed"
		if got := AutomaticNetworkDisplay(row); got.Label != "ﾜｯﾁｮｲ" {
			t.Fatal("provider label leaked into fixed line", got)
		}
		row.Kind = "mixed"
		if provider == "freebit" && AutomaticNetworkDisplay(row).Label != "ﾜｯﾁｮﾏｾﾞ" {
			t.Fatal("unknown-only provider changed mixed display")
		}
	}
}
