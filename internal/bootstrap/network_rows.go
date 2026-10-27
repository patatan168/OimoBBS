// 大規模な自動分類表を圧縮保存し、分類専用の保存上限と厳密な行検査を維持する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const networkPackedThreshold = 1024
const networkRowsJSONLimit = 6 << 20

type networkRows []identity.NetworkClass
type packedNetworkRows struct {
	Encoding string `json:"encoding"`
	Data     string `json:"data"`
}

// MarshalJSON は小さな従来配列を維持し、1024行を超える表をZstandardで有界に保存する。
func (rows networkRows) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal([]identity.NetworkClass(rows))
	if err != nil || len(rows) <= networkPackedThreshold {
		return raw, err
	}
	if len(raw) > networkRowsJSONLimit {
		return nil, errNetworkData
	}
	data, err := networkRowCompression.compress(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(packedNetworkRows{Encoding: "zstd-json-v1", Data: data})
}

// UnmarshalJSON は従来の厳密な行配列と、新reader用の圧縮表だけを受け入れる。
// reader102のZstandardだけを受け入れ、全行の完全型とprefixを検査する。
func (rows *networkRows) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return errNetworkData
	}
	if raw[0] == '{' {
		var packed packedNetworkRows
		if strictjson.DecodeLimit(raw, &packed, store.MaxNetworkValueJSON) != nil || packed.Encoding != "zstd-json-v1" {
			return errNetworkData
		}
		value, err := decodedNetworkRows.decode(packed.Data)
		if err != nil {
			return errNetworkData
		}
		*rows = value
		return nil
	}
	value, err := decodeNetworkRowArray(raw, false)
	if err == nil {
		*rows = value
	}
	return err
}

// decodeNetworkRowArray は展開済み配列も全行の型・重複・CIDRを検査する。
func decodeNetworkRowArray(raw []byte, large bool) (networkRows, error) {
	if len(raw) > strictjson.MaxBytes-32 {
		if !large {
			return nil, errNetworkData
		}
		value, err := decodeLargeNetworkRows(raw)
		if err != nil {
			return nil, err
		}
		return value, nil
	}
	var value struct {
		Rows []identity.NetworkClass `json:"rows"`
	}
	wrapped := append([]byte(`{"rows":`), raw...)
	wrapped = append(wrapped, '}')
	if strictjson.Decode(wrapped, &value) != nil || value.Rows == nil {
		return nil, errNetworkData
	}
	if _, err := identity.CompileNetworks(value.Rows, networkRowLimit); err != nil {
		return nil, errNetworkData
	}
	return value.Rows, nil
}

// networkRowsPacked は保存値が旧readerの解釈できない圧縮表を使うか確認する。
func networkRowsPacked(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	value := bytes.TrimSpace(fields["rows"])
	return len(value) > 0 && value[0] == '{'
}

// decodeLargeNetworkRows は最大6MiB/4万行を一行ずつ厳密に復号し、全体JSONの上限を緩めない。
func decodeLargeNetworkRows(raw []byte) ([]identity.NetworkClass, error) {
	if len(raw) > networkRowsJSONLimit {
		return nil, errNetworkData
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('[') {
		return nil, errNetworkData
	}
	decoded := newLargeNetworkRowDecoder(len(raw))
	for d.More() {
		if decoded.count >= networkRowLimit {
			return nil, errNetworkData
		}
		var body json.RawMessage
		if d.Decode(&body) != nil {
			return nil, errNetworkData
		}
		if decoded.add(body) != nil {
			return nil, errNetworkData
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim(']') {
		return nil, errNetworkData
	}
	var trailing json.RawMessage
	if d.Decode(&trailing) != io.EOF {
		return nil, errNetworkData
	}
	return decoded.finish()
}
