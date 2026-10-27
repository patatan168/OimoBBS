// 大きい取得元・表示カテゴリーだけを圧縮し、管理APIの通常JSONと分類専用の制御上限を維持する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
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

// MarshalJSON は64KiBを超える設定だけZstandardで包む。小さい従来設定はそのまま保存する。
func (v networkState) MarshalJSON() ([]byte, error) {
	config, err := json.Marshal(v.Config)
	if err != nil {
		return nil, err
	}
	if len(config) > 64<<10 {
		if len(config) > strictjson.MaxBytes {
			return nil, errNetworkData
		}
		compressed, e := networkConfigCompression.compress(config)
		if e != nil {
			return nil, e
		}
		config, err = json.Marshal(packedNetworkRows{Encoding: "zstd-config-v1", Data: compressed})
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(networkStateWire{v.AccessData, v.Version, config, v.Rows, v.LastAttempt, v.LastSuccess, v.AttemptVersion, v.AppliedVersion, v.Error})
}

// UnmarshalJSON は設定の展開上限を1MiBに保ち、未知・重複キーと非正規圧縮データを拒否する。
func (v *networkState) UnmarshalJSON(raw []byte) error {
	var w networkStateWire
	if strictjson.DecodeLimit(raw, &w, store.MaxNetworkValueJSON) != nil {
		return errNetworkData
	}
	var header map[string]json.RawMessage
	if json.Unmarshal(w.Config, &header) != nil {
		return errNetworkData
	}
	if _, packed := header["encoding"]; packed {
		var p packedNetworkRows
		if strictjson.Decode(w.Config, &p) != nil || p.Encoding != "zstd-config-v1" {
			return errNetworkData
		}
		if p.Encoding == "zstd-config-v1" && !networkZstdValue(p.Data) {
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

// networkStateZstd は新しいcodecまたは拡張サイズを旧readerへ渡さないための境界。
func networkStateZstd(raw []byte, v networkState) bool {
	if len(raw) > strictjson.MaxBytes || v.AccessData != nil && networkZstdValue(v.AccessData.Countries) {
		return true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, key := range []string{"rows", "config"} {
		var p packedNetworkRows
		if json.Unmarshal(fields[key], &p) == nil && (p.Encoding == "zstd-json-v1" || p.Encoding == "zstd-config-v1") {
			return true
		}
	}
	var access struct {
		Packed string `json:"packed_prefixes"`
	}
	return json.Unmarshal(fields["access_data"], &access) == nil && networkZstdValue(access.Packed)
}

// networkRequiresZstdReader は新規保存がZstandardを使うときだけreader境界を上げる。
func networkRequiresZstdReader(v networkState) bool {
	if len(v.Rows) > networkPackedThreshold || v.AccessData != nil && v.AccessData.Countries != "" {
		return true
	}
	config, err := json.Marshal(v.Config)
	if err == nil && len(config) > 64<<10 {
		return true
	}
	raw, err := json.Marshal(v)
	return err == nil && len(raw) > strictjson.MaxBytes
}
