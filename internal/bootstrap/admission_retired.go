// 署名検証済み回収履歴だけを、満了済み受理枠として規制復旧から除外する。
package bootstrap

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
)

// retiredRateHistoryRow はSchemaだけで通常履歴を読み飛ばさず、内部証明と現在時計を照合する。
func retiredRateHistoryRow(row boardRateRecord, now domain.Time) (bool, error) {
	if row.record.Schema != app.RetiredRateSchema && row.record.Retirement == nil {
		return false, nil
	}
	if e := app.ValidateRetiredRateRecord(row.owner, row.key, row.record, now); e != nil {
		return false, e
	}
	return true, nil
}
