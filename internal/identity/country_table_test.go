// 国コード候補の重複排除・順序・返却値の独立性と大規模表での取得コストを検証する。
package identity

import (
	"net/netip"
	"slices"
	"testing"
)

func TestCountryCodesIndependentAndSorted(t *testing.T) {
	table, err := CompileCountries([]CountryNetwork{{netip.MustParsePrefix("11.0.0.0/8"), "US"}, {netip.MustParsePrefix("12.0.0.0/8"), "JP"}, {netip.MustParsePrefix("13.0.0.0/8"), "JP"}})
	if err != nil {
		t.Fatal(err)
	}
	codes := table.Codes()
	if !slices.Equal(codes, []string{"JP", "US"}) {
		t.Fatal(codes)
	}
	codes[0] = "XX"
	if !slices.Equal(table.Codes(), []string{"JP", "US"}) {
		t.Fatal("returned codes mutated immutable table")
	}
	var empty *CountryTable
	if empty.Codes() != nil {
		t.Fatal("nil table")
	}
}

func BenchmarkCountryCodesLarge(b *testing.B) {
	rows := make([]CountryNetwork, 300000)
	for i := range rows {
		rows[i] = CountryNetwork{netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i >> 16), byte(i >> 8), byte(i)}), 32), "JP"}
	}
	table, err := CompileCountries(rows)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = table.Codes()
	}
}

// TestCountryConflicts は同一範囲の国不明・日本優先・同国重複が入力順に依存しないことを検証する。
func TestCountryConflicts(t *testing.T) {
	for _, prefix := range []string{"198.51.100.0/24", "2001:db8::/32"} {
		for _, tc := range []struct {
			codes []string
			want  string
		}{
			{[]string{"US", "DE", "US"}, ""},
			{[]string{"US", "DE", "JP", "US"}, "JP"},
			{[]string{"US", "US"}, "US"},
		} {
			for rotation := range len(tc.codes) {
				codes := append(slices.Clone(tc.codes[rotation:]), tc.codes[:rotation]...)
				for range 2 {
					slices.Reverse(codes)
					rows := []CountryNetwork{}
					for _, code := range codes {
						rows = append(rows, CountryNetwork{netip.MustParsePrefix(prefix), code})
					}
					table, err := CompileCountries(rows)
					if err != nil {
						t.Fatal(err)
					}
					code, cidr, ok := table.Match(netip.MustParsePrefix(prefix).Addr())
					if !ok || cidr != prefix || code != tc.want || !table.HasDuplicatePrefixes() {
						t.Fatal(codes, code, cidr, ok)
					}
					expected := []string{}
					if tc.want != "" {
						expected = append(expected, tc.want)
					}
					if !slices.Equal(table.Codes(), expected) {
						t.Fatal("unresolved country offered as candidate", table.Codes())
					}
				}
			}
		}
	}
}

// TestCountryConflictStopsFallback は不明な最長一致を広い国や日本表の非掲載判定で埋めないことを検証する。
func TestCountryConflictStopsFallback(t *testing.T) {
	table, err := CompileCountries([]CountryNetwork{
		{netip.MustParsePrefix("198.51.0.0/16"), "GB"},
		{netip.MustParsePrefix("198.51.100.0/24"), "US"},
		{netip.MustParsePrefix("198.51.100.0/24"), "DE"},
	})
	if err != nil {
		t.Fatal(err)
	}
	japan, err := CompileNetworks([]NetworkClass{{CIDR: "203.0.113.0/24", Kind: "unknown", Label: "ﾜｯﾁｮｲ", Suffix: "0"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := &NetworkClassifier{Access: &AccessIndex{Countries: table, Japan: japan}}
	ip := netip.MustParseAddr("198.51.100.1")
	if got := c.ClassifyAccess(ip); got.Country != "unknown" || got.CountryCode != "" || got.CountryCIDR != "198.51.100.0/24" {
		t.Fatal(got)
	}
	c.Access.Overrides = []AccessOverride{{CIDR: "198.51.100.0/24", Country: "jp", VPN: "auto"}}
	if got := c.ClassifyAccess(ip); got.Country != "jp" || got.CountryCode != "JP" {
		t.Fatal("manual override", got)
	}
	c.Access.Overrides = nil
	c.Access.Japan, _ = CompileNetworks([]NetworkClass{{CIDR: "198.51.100.0/24", Kind: "unknown", Label: "ﾜｯﾁｮｲ", Suffix: "0"}}, 1)
	if got := c.ClassifyAccess(ip); got.Country != "jp" || got.CountryCode != "JP" {
		t.Fatal("Japan feed priority", got)
	}
	// 次の成功表で重複が消えれば、不明判定も解消する。
	c.Access.Japan = nil
	c.Access.Countries, _ = CompileCountries([]CountryNetwork{{netip.MustParsePrefix("198.51.100.0/24"), "US"}})
	if got := c.ClassifyAccess(ip); got.Country != "foreign" || got.CountryCode != "US" {
		t.Fatal("next successful table", got)
	}
}
