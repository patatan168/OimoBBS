// 初回作成時のdirectoryをそのまま読み、明示した表示名のある登録情報だけ新形式として読む。
package bootstrap

import (
	"encoding/json"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// UnmarshalJSON は省略キーを一般的に許可せず、旧5項目と名前付き6項目を個別に完全検査する。
func (d *boardDirectory) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(raw, &fields); err != nil {
		return err
	}
	if _, ok := fields["name"]; ok {
		type wire boardDirectory
		var v wire
		if err := strictjson.Decode(raw, &v); err != nil {
			return err
		}
		if !validName(v.Name) {
			return store.ErrCorrupt
		}
		*d = boardDirectory(v)
		return nil
	}
	var v struct {
		Key        string     `json:"key"`
		Aliases    []string   `json:"aliases"`
		Status     string     `json:"status"`
		CategoryID *domain.ID `json:"category_id"`
		JobID      domain.ID  `json:"job_id"`
	}
	if err := strictjson.Decode(raw, &v); err != nil {
		return err
	}
	*d = boardDirectory{Key: v.Key, Aliases: v.Aliases, Status: v.Status, CategoryID: v.CategoryID, JobID: v.JobID}
	return nil
}
