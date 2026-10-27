// Zstandardの独立復号一致・破損拒否・展開上限・reader境界を検証する。
package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"oimobbs/internal/store"
	"oimobbs/internal/testutil"
	"testing"
)

func TestNetworkZstdCodec(t *testing.T) {
	body := bytes.Repeat([]byte("network 日本 VPN 192.0.2.0/24\n"), 60000)
	value, err := compressNetworkData(body)
	if err != nil || !networkZstdValue(value) {
		t.Fatal(err)
	}
	raw, err := decodeNetworkBase64(value)
	if err != nil {
		t.Fatal(err)
	}
	independent, err := testutil.DecodeZstd(raw[12:])
	if err != nil || !bytes.Equal(independent, body) {
		t.Fatal("独立復号の不一致", err)
	}
	got, err := decompressNetworkData(value, len(body))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal(err)
	}
	if _, err := decompressNetworkData(value, len(body)-1); err == nil {
		t.Fatal("展開上限を超えた")
	}
	for _, index := range []int{0, 4, 8, 12} {
		bad := bytes.Clone(raw)
		bad[index] ^= 1
		if _, err := decompressNetworkData(base64.StdEncoding.EncodeToString(bad), len(body)); err == nil {
			t.Fatal("改変を受理した", index)
		}
	}
	for _, bad := range [][]byte{raw[:len(raw)-1], append(bytes.Clone(raw), 0), append(bytes.Clone(raw), raw[12:]...)} {
		if _, err := decompressNetworkData(base64.StdEncoding.EncodeToString(bad), len(body)); err == nil {
			t.Fatal("切断・末尾・連結を受理した")
		}
	}
	declared := bytes.Clone(raw)
	binary.LittleEndian.PutUint32(declared[4:], 0xffffffff)
	if _, err := decompressNetworkData(base64.StdEncoding.EncodeToString(declared), countryUnpackedLimit); err == nil {
		t.Fatal("巨大な宣言長を受理した")
	}
	if _, err := decompressNetworkData(value+"\n", countryUnpackedLimit); err == nil {
		t.Fatal("非正規base64を受理した")
	}
	if _, err := decompressNetworkData(string(bytes.Repeat([]byte("A"), store.MaxNetworkValueJSON+1)), countryUnpackedLimit); err == nil {
		t.Fatal("保存上限を超えた")
	}
}
func TestNetworkZstdReaderEscapedKeys(t *testing.T) {
	raw := []byte(`{"config":{"encoding":"zstd-config-v1","data":""}}`)
	escaped := bytes.ReplaceAll(raw, []byte("encoding"), []byte(`enc\u006fding`))
	for _, value := range [][]byte{raw, escaped} {
		if !networkStateZstd(value, networkState{}) {
			t.Fatal("reader境界を迂回した")
		}
	}
	p, _ := compressNetworkData([]byte("prefix"))
	raw, _ = json.Marshal(map[string]any{"access_data": map[string]string{"packed_prefixes": p}})
	if !networkStateZstd(raw, networkState{}) {
		t.Fatal("prefixのreader境界がない")
	}
}
