// 閲覧設定の旧形式を厳密に読み取り、特殊アドレスの個別設定を追加した形式へ引き継ぐ。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/strictjson"
)

// UnmarshalJSON は旧形式と新形式を区別する。新項目が片方だけある入力や未知・欠落キーは拒否する。
func (p *ReadingPolicy) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(raw, &fields); err != nil {
		return err
	}
	if _, local := fields["allow_local_ip"]; local {
		return p.decodeCurrent(raw)
	}
	if _, loopback := fields["allow_loopback_ip"]; loopback {
		return p.decodeCurrent(raw)
	}
	var legacy struct {
		Enabled      bool                  `json:"enabled"`
		Network      NetworkAccessSettings `json:"network"`
		AllowedCIDRs []string              `json:"allowed_cidrs"`
		DeniedCIDRs  []string              `json:"denied_cidrs"`
		DeniedAgents []string              `json:"denied_agents"`
		DenyCrawlers bool                  `json:"deny_crawlers"`
	}
	if err := strictjson.Decode(raw, &legacy); err != nil {
		return err
	}
	*p = ReadingPolicy{Enabled: legacy.Enabled, Network: legacy.Network, AllowedCIDRs: legacy.AllowedCIDRs, DeniedCIDRs: legacy.DeniedCIDRs, DeniedAgents: legacy.DeniedAgents, DenyCrawlers: legacy.DenyCrawlers}
	return nil
}

// decodeCurrent は独自復号器を外した型で新形式の全キーと型を検査する。
func (p *ReadingPolicy) decodeCurrent(raw []byte) error {
	type current ReadingPolicy
	var v current
	if err := strictjson.Decode(raw, &v); err != nil {
		return err
	}
	*p = ReadingPolicy(v)
	return nil
}

// readingMinimumReader は特殊アドレス設定・混在回線・特殊用途の拒否を扱える最低reader版を返す。
func readingMinimumReader(raw []byte) uint32 {
	var policy ReadingPolicy
	if json.Unmarshal(raw, &policy) == nil && specialNetworkAccess(&policy.Network) {
		return specialNetworkReader
	}
	if json.Unmarshal(raw, &policy) == nil && mixedNetworkAccess(&policy.Network) {
		return mixedNetworkReader
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if _, ok := fields["allow_local_ip"]; ok {
		return 83
	}
	return 82
}
