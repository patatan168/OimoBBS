// 板ごとの通報有効状態と集計開始時刻を保存し、再有効化時の旧票の復元を防ぐ。
package bootstrap

import (
	"errors"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// boardAutoReportSettings は無効期間の票を再起動後にも除外する板設定。
type boardAutoReportSettings struct {
	Enabled bool        `json:"enabled"`
	Since   domain.Time `json:"since_ns"`
}

// ErrAutoReportDisabled は対象板が通報受付を無効にしている場合に返す。
var ErrAutoReportDisabled = errors.New("automatic reports are disabled for this board")

// boardAutoReportsEnabled は設定のない旧板を有効として扱う。
func boardAutoReportsEnabled(v *boardAutoReportSettings) bool { return v == nil || v.Enabled }

// validateBoardAutoReports は集計開始時刻の巻き戻しと不正な保存状態を拒否する。
func validateBoardAutoReports(old, next *boardAutoReportSettings) error {
	if next == nil {
		if old != nil {
			return store.ErrCorrupt
		}
		return nil
	}
	if next.Since < 0 || next.Since > domain.Time(time.Now().UnixNano()) || !next.Enabled && next.Since == 0 {
		return store.ErrCorrupt
	}
	if old != nil && (next.Since < old.Since || old.Enabled != next.Enabled && next.Since <= old.Since || old.Enabled == next.Enabled && next.Since != old.Since) {
		return store.ErrCorrupt
	}
	return nil
}

// receiptSnapshotForBoard は通報を停止した板の案内を置き換え、古い案内のETagを失効させる。
func receiptSnapshotForBoard(origin, slug string, p ReportPolicy, settings *boardAutoReportSettings) (*app.PostingSnapshot, error) {
	if boardAutoReportsEnabled(settings) {
		return receiptSnapshotWithPolicy(origin, slug, p)
	}
	dat, err := compat.DAT(domain.Post{Number: 1, Kind: "system", Visibility: "visible", Name: "通報案内", Body: "この板の通報機能は現在無効です。通報受付スレッドからの通報は受け付けません。通常スレッドの !report は通常の公開投稿として扱われ、自動停止には集計されません。", Identity: domain.Identity{DateText: "1970/01/01(木) 09:00:01"}}, reportReceiptTitle)
	if err != nil {
		return nil, err
	}
	return app.NewSystemThreadSnapshot(reportReceiptTitle, dat), nil
}
