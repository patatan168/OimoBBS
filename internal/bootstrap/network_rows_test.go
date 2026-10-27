// 圧縮回線表の往復、旧配列の保持、展開上限・未知/重複キー拒否を確認する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkPackedRowsStrictRoundTrip(t *testing.T) {
	rows := networkRows{}
	for index := 0; index < 1200; index++ {
		rows = append(rows, identity.NetworkClass{CIDR: fmt.Sprintf("198.18.%d.%d/32", index/256, index%256), Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0", Provider: "sonet"})
	}
	raw, err := json.Marshal(struct {
		Rows networkRows `json:"rows"`
	}{rows})
	if err != nil || !networkRowsPacked(raw) || len(raw) > 10000 {
		t.Fatal("not packed", len(raw), err)
	}
	var decoded struct {
		Rows networkRows `json:"rows"`
	}
	if err = strictjson.Decode(raw, &decoded); err != nil || !reflect.DeepEqual(decoded.Rows, rows) {
		t.Fatal("packed roundtrip", err)
	}
	small, err := json.Marshal(struct {
		Rows networkRows `json:"rows"`
	}{rows[:1]})
	if err != nil || networkRowsPacked(small) || strictjson.Decode(small, &decoded) != nil {
		t.Fatal("legacy array lost", err)
	}
	for _, input := range []string{
		`{"rows":null}`,
		`{"rows":{"encoding":"other","data":""}}`,
		`{"rows":{"encoding":"gzip-json-v1","data":null}}`,
		`{"rows":{"encoding":"gzip-json-v1","data":"","extra":true}}`,
		`{"rows":{"encoding":"gzip-json-v1","data":"","data":""}}`,
		`{"rows":[{"cidr":"192.0.2.0/24","kind":"fixed","label":"ﾜｯﾁｮｲ","suffix":"0","provider":"sonet","extra":true}]}`,
		`{"rows":[{"cidr":"192.0.2.0/24","kind":"fixed","label":"ﾜｯﾁｮｲ","suffix":"0"}]}`,
	} {
		if strictjson.Decode([]byte(input), &decoded) == nil {
			t.Fatal("invalid rows accepted", input)
		}
	}
	// gzipの小さな本文でも展開後の容量・構造・末尾を検査する。
	for _, content := range []string{strings.Repeat(" ", strictjson.MaxBytes+1), `[{"cidr":"192.0.2.0/24","kind":"fixed","label":"ﾜｯﾁｮｲ","suffix":"0","provider":"sonet","extra":true}]`, `null`} {
		encoded, _ := compressNetworkData([]byte(content))
		packed, _ := json.Marshal(struct {
			Rows packedNetworkRows `json:"rows"`
		}{packedNetworkRows{"zstd-json-v1", encoded}})
		if strictjson.Decode(packed, &decoded) == nil {
			t.Fatal("expanded invalid rows accepted")
		}
	}
}
