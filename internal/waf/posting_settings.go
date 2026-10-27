// 投稿専用の有界な保護設定。通常枠と独立に保存し、適用時は小さい方を使う。
package waf

import (
	"encoding/json"
	"oimobbs/internal/strictjson"
)

// PostingSettings は確認往復を含む全投稿入口が共有する頻度・瞬間・同時処理の上限。
type PostingSettings struct {
	ClientRate       int `json:"client_rate"`
	ClientBurst      int `json:"client_burst"`
	GlobalRate       int `json:"global_rate"`
	GlobalBurst      int `json:"global_burst"`
	ClientConcurrent int `json:"client_concurrent"`
	GlobalConcurrent int `json:"global_concurrent"`
}

// DefaultPostingSettings は従来と同じ保護強度を返す。
func DefaultPostingSettings() PostingSettings { return PostingSettings{10, 30, 60, 120, 8, 32} }

// Valid は保護無効化のゼロ、負数、過大値と枠内の大小関係の不整合を拒否する。
// 通常枠より大きい設定は許すが、実際の受付では通常枠を超えない。
func (s PostingSettings) Valid() bool {
	return s.ClientRate >= 1 && s.ClientRate <= 10000 && s.ClientBurst >= s.ClientRate && s.ClientBurst <= 100000 &&
		s.GlobalRate >= s.ClientRate && s.GlobalRate <= 100000 && s.GlobalBurst >= s.GlobalRate && s.GlobalBurst >= s.ClientBurst && s.GlobalBurst <= 200000 &&
		s.ClientConcurrent >= 1 && s.ClientConcurrent <= 128 && s.GlobalConcurrent >= s.ClientConcurrent && s.GlobalConcurrent <= 2048
}

// UnmarshalJSON は投稿枠と回線別スイッチの未保存時だけ従来の既定値を使う。
// 指定されたpostingは全項目を要求し、未知キー・重複・null・不正整数を受け付けない。
func (s *TrafficSettings) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(raw, &fields); err != nil {
		return err
	}
	changed := false
	if _, present := fields["client_enabled"]; !present {
		fields["client_enabled"] = json.RawMessage("true")
		changed = true
	}
	if _, present := fields["posting"]; !present {
		fields["posting"], _ = json.Marshal(DefaultPostingSettings())
		changed = true
	}
	if changed {
		var err error
		raw, err = json.Marshal(fields)
		if err != nil {
			return err
		}
	}
	type plain TrafficSettings
	var value plain
	if err := strictjson.Decode(raw, &value); err != nil {
		return err
	}
	*s = TrafficSettings(value)
	return nil
}
