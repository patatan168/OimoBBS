// 大規模な自動分類表を圧縮保存し、制御JSONの1MiB上限と厳密な行検査を維持する。
package bootstrap

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
)

const networkPackedThreshold = 1024
const networkRowsJSONLimit = 6 << 20

type networkRows []identity.NetworkClass
type packedNetworkRows struct {
	Encoding string `json:"encoding"`
	Data     string `json:"data"`
}

// MarshalJSON は小さな従来配列を維持し、1024行を超える表をgzipで有界に保存する。
func (rows networkRows) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal([]identity.NetworkClass(rows))
	if err != nil || len(rows) <= networkPackedThreshold {
		return raw, err
	}
	if len(raw) > networkRowsJSONLimit {
		return nil, errNetworkData
	}
	var buffer bytes.Buffer
	level := gzip.DefaultCompression
	if len(raw) > strictjson.MaxBytes-32 {
		level = gzip.BestCompression
	}
	writer, _ := gzip.NewWriterLevel(&buffer, level)
	if _, err = writer.Write(raw); err != nil {
		return nil, err
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	encoding := "gzip-json-v1"
	if len(raw) > strictjson.MaxBytes-32 {
		encoding = "gzip-json-v2"
	}
	return json.Marshal(packedNetworkRows{Encoding: encoding, Data: base64.StdEncoding.EncodeToString(buffer.Bytes())})
}

// UnmarshalJSON は従来の厳密な行配列と、新reader用の圧縮表だけを受け入れる。
// v1は1MiB、reader92のv2は6MiB/4万行まで。行ごとに未知/重複キー・null・不正行を拒否する。
func (rows *networkRows) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return errNetworkData
	}
	large := false
	if raw[0] == '{' {
		var packed packedNetworkRows
		if strictjson.Decode(raw, &packed) != nil || (packed.Encoding != "gzip-json-v1" && packed.Encoding != "gzip-json-v2") {
			return errNetworkData
		}
		compressed, err := base64.StdEncoding.Strict().DecodeString(packed.Data)
		if err != nil || base64.StdEncoding.EncodeToString(compressed) != packed.Data {
			return errNetworkData
		}
		input := bytes.NewReader(compressed)
		reader, err := gzip.NewReader(input)
		if err != nil {
			return errNetworkData
		}
		reader.Multistream(false)
		limit := strictjson.MaxBytes - 32
		if packed.Encoding == "gzip-json-v2" {
			large = true
			limit = networkRowsJSONLimit
		}
		raw, err = io.ReadAll(io.LimitReader(reader, int64(limit)+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || input.Len() != 0 || len(raw) > limit {
			return errNetworkData
		}
	}
	if len(raw) > strictjson.MaxBytes-32 {
		if !large {
			return errNetworkData
		}
		value, err := decodeLargeNetworkRows(raw)
		if err != nil {
			return err
		}
		*rows = value
		return nil
	}
	var value struct {
		Rows []identity.NetworkClass `json:"rows"`
	}
	wrapped := append([]byte(`{"rows":`), raw...)
	wrapped = append(wrapped, '}')
	if strictjson.Decode(wrapped, &value) != nil || value.Rows == nil {
		return errNetworkData
	}
	if _, err := identity.CompileNetworks(value.Rows, networkRowLimit); err != nil {
		return errNetworkData
	}
	*rows = value.Rows
	return nil
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
	rows := []identity.NetworkClass{}
	for d.More() {
		if len(rows) >= networkRowLimit {
			return nil, errNetworkData
		}
		var body json.RawMessage
		var row identity.NetworkClass
		if d.Decode(&body) != nil || strictjson.Decode(body, &row) != nil {
			return nil, errNetworkData
		}
		rows = append(rows, row)
	}
	if token, err = d.Token(); err != nil || token != json.Delim(']') {
		return nil, errNetworkData
	}
	var trailing json.RawMessage
	if d.Decode(&trailing) != io.EOF {
		return nil, errNetworkData
	}
	if _, err := identity.CompileNetworks(rows, networkRowLimit); err != nil {
		return nil, errNetworkData
	}
	return rows, nil
}
