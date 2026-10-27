// 条件付き投稿枠の固定仕様。補充と長期窓を既存の61分受理履歴から復元する。
package bootstrap

import (
	"oimobbs/internal/abuse"
	"time"
)

// AdminRateOverride は条件一致時の追加枠。通常のIP/network/site/token枠を無効にしない。
// WindowLimitは現在分＋過去60分の上限で、0は長期窓だけを無効にする。
type AdminRateOverride struct {
	RefillSeconds uint32 `json:"refill_seconds"`
	Burst         uint32 `json:"burst"`
	WindowLimit   uint32 `json:"window_limit"`
}

func (v AdminRateOverride) valid() bool {
	return v.RefillSeconds >= 1 && v.RefillSeconds <= 3600 && v.Burst >= 1 && uint64(v.RefillSeconds)*uint64(v.Burst) <= 3600 && v.WindowLimit <= 1000000
}
func (v AdminRateOverride) spec() abuse.RateSpec {
	return abuse.RateSpec{Tokens: 1, Every: time.Duration(v.RefillSeconds) * time.Second, Burst: v.Burst, WindowLimit: v.WindowLimit}
}

// cloneRateOverride は管理DTO・保存入力に所有者の可変pointerを共有しない。
func cloneRateOverride(value *AdminRateOverride) *AdminRateOverride {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
