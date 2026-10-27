// reader102の大規模回線表・設定圧縮を往復し、旧形式・展開上限・重複キーの拒否を確認する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestNetworkLargePackedRowsRoundTripAndStrictness(t *testing.T) {
	rows := networkRows{}
	for i := 0; i < 12000; i++ {
		rows = append(rows, identity.NetworkClass{CIDR: fmt.Sprintf("198.18.%d.%d/32", i/256, i%256), Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V", Provider: "cloud"})
	}
	raw, err := json.Marshal(struct {
		Rows networkRows `json:"rows"`
	}{rows})
	if err != nil || !bytes.Contains(raw, []byte("zstd-json-v1")) || len(raw) > strictjson.MaxBytes {
		t.Fatal(len(raw), err)
	}
	var restored struct {
		Rows networkRows `json:"rows"`
	}
	if err = strictjson.Decode(raw, &restored); err != nil || !reflect.DeepEqual(rows, restored.Rows) {
		t.Fatal("large roundtrip", err)
	}
	old := bytes.ReplaceAll(raw, []byte("zstd-json-v1"), []byte("gzip-json-v1"))
	if strictjson.Decode(old, &restored) == nil {
		t.Fatal("v1 expanded limit changed")
	}
	for _, body := range []string{strings.Repeat(" ", networkRowsJSONLimit+1), `[{"cidr":"192.0.2.0/24","kind":"hosting","label":"ｸﾓﾉｳｴ","label":"duplicate","suffix":"V","provider":"cloud"}]`, `[{"cidr":"192.0.2.0/24","kind":"hosting","label":"ｸﾓﾉｳｴ","suffix":"V","provider":"cloud","extra":0}]`, `null`, `[] {}`} {
		compressed, _ := compressNetworkData([]byte(body))
		packed, _ := json.Marshal(struct {
			Rows packedNetworkRows `json:"rows"`
		}{packedNetworkRows{"zstd-json-v1", compressed}})
		if strictjson.Decode(packed, &restored) == nil {
			t.Fatal("invalid v2 accepted")
		}
	}
}

func TestNetworkLargeConfigRoundTripAndReader(t *testing.T) {
	state := networkState{Version: 1, Config: defaultNetworkConfig(), Rows: networkRows{}}
	state.Config.Sources = defaultNetworkSources()
	raw, err := json.Marshal(state)
	if err != nil || !networkStateZstd(raw, state) {
		t.Fatal("config not packed", err)
	}
	var restored networkState
	if err = strictjson.Decode(raw, &restored); err != nil || !reflect.DeepEqual(state, restored) {
		t.Fatal("config roundtrip", err)
	}
	if !networkRequiresSpecialReader(state) {
		t.Fatal("old reader allowed")
	}
	changed := bytes.ReplaceAll(raw, []byte("zstd-config-v1"), []byte("zstd-config-v9"))
	if strictjson.Decode(changed, &restored) == nil {
		t.Fatal("unknown config codec accepted")
	}
	configAPI, _ := json.Marshal(state.Config)
	if bytes.Contains(configAPI, []byte("zstd-config")) {
		t.Fatal("API format changed")
	}
	var config NetworkConfig
	if strictjson.Decode(configAPI, &config) != nil {
		t.Fatal("API config no longer readable")
	}
}

func TestNetworkLargeRowsCoreEquivalence(t *testing.T) {
	previous := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(previous)
	rows := make([]identity.NetworkClass, 12000)
	for i := range rows {
		rows[i] = identity.NetworkClass{CIDR: fmt.Sprintf("198.18.%d.%d/32", i/256, i%256), Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V", Provider: "cloud"}
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, cores := range []int{1, 4} {
		runtime.GOMAXPROCS(cores)
		got, err := decodeLargeNetworkRows(raw)
		if err != nil || !reflect.DeepEqual(got, rows) {
			t.Fatal(cores, err)
		}
		bad := bytes.Replace(raw, []byte(`"kind":"hosting"`), []byte(`"kind":"hosting","kind":"fixed"`), 1)
		if _, err := decodeLargeNetworkRows(bad); err == nil {
			t.Fatal("重複キーを受理した", cores)
		}
		duplicate := append(bytes.Clone(raw[:len(raw)-1]), append([]byte(","), append(bytes.Clone(raw[1:bytes.IndexByte(raw, '}')+1]), ']')...)...)
		if _, err := decodeLargeNetworkRows(duplicate); err == nil {
			t.Fatal("重複prefixを受理した", cores)
		}
	}
}
