// 公開本体回収前の順位高水位を、厳密な単調更新として検証する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func validateBumpWatermarkUpdate(key string, old, next []byte) error {
	var before, after struct {
		Last domain.U64 `json:"last_removed_bump"`
	}
	if key != "ranking" || strictjson.Decode(old, &before) != nil || strictjson.Decode(next, &after) != nil || after.Last <= before.Last {
		return store.ErrCorrupt
	}
	return nil
}
