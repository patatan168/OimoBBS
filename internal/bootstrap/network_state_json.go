// 大きい取得元・表示カテゴリーだけを圧縮し、管理APIの通常JSONと制御frameの1MiB上限を維持する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

type networkStateWire struct {
	AccessData     *networkAccessData `json:"access_data"`
	Version        domain.U64         `json:"version"`
	Config         json.RawMessage    `json:"config"`
	Rows           networkRows        `json:"rows"`
	LastAttempt    domain.Time        `json:"last_attempt_ns"`
	LastSuccess    domain.Time        `json:"last_success_ns"`
	AttemptVersion domain.U64         `json:"attempt_version"`
	AppliedVersion domain.U64         `json:"applied_version"`
	Error          string             `json:"error_code"`
}

// MarshalJSON は64KiBを超える設定だけgzipで包む。小さい従来設定はそのまま保存する。
func (v networkState) MarshalJSON() ([]byte, error) {
	config, err := json.Marshal(v.Config)
	if err != nil {
		return nil, err
	}
	if len(config) > 64<<10 {
		if len(config) > strictjson.MaxBytes {
			return nil, errNetworkData
		}
		compressed, e := compressNetworkData(config)
		if e != nil {
			return nil, e
		}
		config, err = json.Marshal(packedNetworkRows{Encoding: "gzip-config-v1", Data: compressed})
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(networkStateWire{v.AccessData, v.Version, config, v.Rows, v.LastAttempt, v.LastSuccess, v.AttemptVersion, v.AppliedVersion, v.Error})
}

// UnmarshalJSON は設定の展開上限を1MiBに保ち、未知・重複キーと非正規gzipを拒否する。
func (v *networkState) UnmarshalJSON(raw []byte) error {
	var w networkStateWire
	if strictjson.Decode(raw, &w) != nil {
		return errNetworkData
	}
	var header map[string]json.RawMessage
	if json.Unmarshal(w.Config, &header) != nil {
		return errNetworkData
	}
	if _, packed := header["encoding"]; packed {
		var p packedNetworkRows
		if strictjson.Decode(w.Config, &p) != nil || p.Encoding != "gzip-config-v1" {
			return errNetworkData
		}
		config, err := decompressNetworkData(p.Data, strictjson.MaxBytes)
		if err != nil {
			return err
		}
		w.Config = config
	}
	var config NetworkConfig
	if strictjson.Decode(w.Config, &config) != nil {
		return errNetworkData
	}
	*v = networkState{w.AccessData, w.Version, config, w.Rows, w.LastAttempt, w.LastSuccess, w.AttemptVersion, w.AppliedVersion, w.Error}
	return nil
}

// networkStatePacked92 は内容が小さくても新しい圧縮表記を使う保存値を旧readerから保護する。
func networkStatePacked92(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, key := range []string{"rows", "config"} {
		body := bytes.TrimSpace(fields[key])
		if len(body) == 0 || body[0] != '{' {
			continue
		}
		var p struct {
			Encoding string `json:"encoding"`
		}
		if json.Unmarshal(body, &p) == nil && (p.Encoding == "gzip-json-v2" || p.Encoding == "gzip-config-v1") {
			return true
		}
	}
	return false
}
