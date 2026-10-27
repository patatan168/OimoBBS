// 日時入力の基準をサーバー時刻に揃え、端末の時計やタイムゾーンに依存させない。
package webui

import (
	"oimobbs/internal/domain"
	"time"
)

func dateNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func dateRFC(value domain.Time) string {
	return time.Unix(0, int64(value)).UTC().Format(time.RFC3339Nano)
}
