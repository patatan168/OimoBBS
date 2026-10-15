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
	if len(raw) > strictjson.MaxBytes-32 {
		return nil, errNetworkData
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err = writer.Write(raw); err != nil {
		return nil, err
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	return json.Marshal(packedNetworkRows{Encoding: "gzip-json-v1", Data: base64.StdEncoding.EncodeToString(buffer.Bytes())})
}

// UnmarshalJSON は従来の厳密な行配列と、新reader用の圧縮表だけを受け入れる。
// 復号・展開にも1MiB上限を適用し、未知/重複キー・null・不正行を許可しない。
func (rows *networkRows) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return errNetworkData
	}
	if raw[0] == '{' {
		var packed packedNetworkRows
		if strictjson.Decode(raw, &packed) != nil || packed.Encoding != "gzip-json-v1" {
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
		raw, err = io.ReadAll(io.LimitReader(reader, strictjson.MaxBytes+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || input.Len() != 0 || len(raw) > strictjson.MaxBytes-32 {
			return errNetworkData
		}
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
