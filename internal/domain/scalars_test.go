// 保存用スカラーの境界値とJSON標準デコードとの受理・値の一致を検査する。
package domain

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

func FuzzScalarJSONEquivalence(f *testing.F) {
	for _, s := range []string{`"0"`, `"-0"`, `"01"`, `"+1"`, `"1"`, `"-1"`, `"18446744073709551615"`, `"18446744073709551616"`, `"9223372036854775807"`, `"-9223372036854775808"`, `"-9223372036854775809"`, `"\u0031"`, ` "1" `, `null`, `1`, `"1" "2"`, `"00000000000000000000000000000001"`, `"ABCDEF00000000000000000000000001"`, `"abcdef00000000000000000000000001"`, `"` + strings.Repeat("a", 64) + `"`, `"` + strings.Repeat("0", 32) + `"`, `"\u0061` + strings.Repeat("a", 63) + `"`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var s string
		decoded := json.Unmarshal(raw, &s) == nil
		u, ue := strconv.ParseUint(s, 10, 64)
		i, ie := strconv.ParseInt(s, 10, 64)
		binary, he := hex.DecodeString(s)
		lower := strings.ToLower(s) == s
		var wantID ID
		copy(wantID[:], binary)
		var wantHash Hash
		copy(wantHash[:], binary)
		cases := []struct {
			dst   json.Unmarshaler
			want  any
			valid bool
		}{
			{func() *U64 { v := U64(42); return &v }(), U64(u), decoded && ue == nil && strconv.FormatUint(u, 10) == s},
			{func() *Time { v := Time(42); return &v }(), Time(i), decoded && ie == nil && strconv.FormatInt(i, 10) == s},
			{&ID{7}, wantID, decoded && he == nil && len(binary) == 16 && lower && wantID != (ID{})},
			{&Hash{7}, wantHash, decoded && he == nil && len(binary) == 32 && lower},
		}
		for _, c := range cases {
			before, _ := json.Marshal(c.dst)
			err := c.dst.UnmarshalJSON(raw)
			if (err == nil) != c.valid {
				t.Fatalf("%T accepts %q: %v, want %v", c.dst, raw, err, c.valid)
			}
			if err != nil {
				after, _ := json.Marshal(c.dst)
				if string(before) != string(after) {
					t.Fatalf("%T changed on failure", c.dst)
				}
				continue
			}
			got, e := json.Marshal(c.dst)
			want, e2 := json.Marshal(c.want)
			if e != nil || e2 != nil || string(got) != string(want) {
				t.Fatalf("%T value: %s != %s", c.dst, got, want)
			}
			var text string
			if json.Unmarshal(got, &text) != nil || text != s {
				t.Fatalf("%T roundtrip: %s != %q", c.dst, got, s)
			}
		}
	})
}

func TestScalarMarshalBoundaries(t *testing.T) {
	for _, u := range []uint64{0, 1, 10, math.MaxUint64} {
		got, e := U64(u).MarshalJSON()
		want, _ := json.Marshal(strconv.FormatUint(u, 10))
		if e != nil || string(got) != string(want) {
			t.Fatal(u, string(got), e)
		}
	}
	for _, i := range []int64{math.MinInt64, -1, 0, 1, math.MaxInt64} {
		got, e := Time(i).MarshalJSON()
		want, _ := json.Marshal(strconv.FormatInt(i, 10))
		if e != nil || string(got) != string(want) {
			t.Fatal(i, string(got), e)
		}
	}
	for _, value := range []json.Marshaler{ID{1, 2, 255}, Hash{}, Hash{255, 1, 2}} {
		got, e := value.MarshalJSON()
		var text string
		if e != nil || json.Unmarshal(got, &text) != nil {
			t.Fatal(value, e)
		}
		var want string
		switch v := value.(type) {
		case ID:
			want = v.String()
		case Hash:
			want = v.String()
		}
		if text != want {
			t.Fatal(text, want)
		}
	}
	if _, e := (ID{}).MarshalJSON(); e == nil {
		t.Fatal("zero ID accepted")
	}
}

func BenchmarkScalarJSON(b *testing.B) {
	for name, raw := range map[string][]byte{"u64": []byte(`"18446744073709551615"`), "time": []byte(`"-9223372036854775808"`), "id": []byte(`"abcdef00000000000000000000000001"`), "hash": []byte(`"` + strings.Repeat("a", 64) + `"`)} {
		b.Run(name, func(b *testing.B) {
			var dst json.Unmarshaler
			switch name {
			case "u64":
				dst = new(U64)
			case "time":
				dst = new(Time)
			case "id":
				dst = new(ID)
			case "hash":
				dst = new(Hash)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := dst.UnmarshalJSON(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
