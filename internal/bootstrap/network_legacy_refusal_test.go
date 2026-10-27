// 旧gzip値を完全に拒否し、Zstandard名への偽装でも旧readerへ分岐しないことを検証する。
package bootstrap

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"testing"
)

func legacyNetworkGzip(t *testing.T, body []byte) string {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, err := z.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

func TestNetworkRejectsLegacyGzipStorage(t *testing.T) {
	rows, _ := json.Marshal([]identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0"}})
	old := legacyNetworkGzip(t, rows)
	for _, encoding := range []string{"gzip-json-v1", "gzip-json-v2", "zstd-json-v1"} {
		raw, _ := json.Marshal(struct {
			Rows packedNetworkRows `json:"rows"`
		}{packedNetworkRows{encoding, old}})
		var restored struct {
			Rows networkRows `json:"rows"`
		}
		if err := strictjson.Decode(raw, &restored); err == nil {
			t.Fatal("旧gzip回線表を受理した", encoding)
		}
	}
	encoded, err := encodeCountries([]identity.CountryNetwork{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Code: "JP"}})
	if err != nil {
		t.Fatal(err)
	}
	country, err := decompressNetworkData(encoded, countryUnpackedLimit)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeCountries(legacyNetworkGzip(t, country)); err == nil {
		t.Fatal("旧gzip国表を受理した")
	}
	prefixes := []byte(`{"japan":["192.0.2.0/24"],"vpn4":["198.51.100.0/24"],"vpn6":["2001:db8::/32"]}`)
	raw, _ := json.Marshal(map[string]any{"countries": encoded, "packed_prefixes": legacyNetworkGzip(t, prefixes), "japan": nil, "vpn4": nil, "vpn6": nil})
	var data networkAccessData
	if err := strictjson.Decode(raw, &data); err == nil {
		t.Fatal("旧gzip接続条件表を受理した")
	}
	state := networkState{Version: 1, Config: defaultNetworkConfig(), Rows: networkRows{}}
	state.Config.Sources = defaultNetworkSources()
	raw, _ = json.Marshal(state)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(state.Config)
	for _, encoding := range []string{"gzip-config-v1", "zstd-config-v1"} {
		fields["config"], _ = json.Marshal(packedNetworkRows{encoding, legacyNetworkGzip(t, config)})
		raw, _ = json.Marshal(fields)
		var restored networkState
		if err := strictjson.Decode(raw, &restored); err == nil {
			t.Fatal("旧gzip設定を受理した", encoding)
		}
	}
}
