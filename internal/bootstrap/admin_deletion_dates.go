// 削除管理のHTTP日付をRFC3339Nanoへ揃え、保存値と旧ns別名を保持する。
package bootstrap

import (
	"time"

	"oimobbs/internal/domain"
)

type deletionHTTPView struct {
	DeletionRecord
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"thread_expires_at"`
	CleanupDueAt string `json:"cleanup_due_at"`
}
type deletionTaskHTTPView struct {
	DeletionCopyTask
	VerifiedAt *string `json:"verified_at"`
}

func adminDate(value domain.Time) string {
	return time.Unix(0, int64(value)).UTC().Format(time.RFC3339Nano)
}
func deletionHTTPValue(v DeletionRecord) deletionHTTPView {
	return deletionHTTPView{v, adminDate(v.Created), adminDate(v.Expires), adminDate(v.CleanupDue)}
}
func deletionHTTPValues(values []DeletionRecord) []deletionHTTPView {
	views := make([]deletionHTTPView, len(values))
	for i, v := range values {
		views[i] = deletionHTTPValue(v)
	}
	return views
}
func deletionTaskHTTPValues(values []DeletionCopyTask) []deletionTaskHTTPView {
	views := make([]deletionTaskHTTPView, len(values))
	for i, v := range values {
		views[i].DeletionCopyTask = v
		if v.Verified != nil {
			formatted := adminDate(*v.Verified)
			views[i].VerifiedAt = &formatted
		}
	}
	return views
}

// CleanupDate は管理画面の掃除予定時刻を他の管理日付と同じ形式で表示する。
func (v DeletionRecord) CleanupDate() string { return adminDate(v.CleanupDue) }
