// 案件範囲に限った必須日末境界とサイト全体の非必須欠測集計を説明する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"strings"
	"time"
)

// evidenceLogExplanationLocked はRepository排他内で板所有列の境界を確認する。
// 欠測集計はsite全体であり、案件の欠測件数へ推定配分しない。
func (r *Repository) evidenceLogExplanationLocked(scope disclosure.Scope) (string, error) {
	b := r.posting[scope.Board]
	text := "必須投稿ログ：確認元がなく未確認です。"
	if b != nil {
		value, e := b.worker.Submit(context.Background(), func() (any, error) { return r.requiredLogExplanationOwned(b, scope), nil })
		if e != nil {
			return "", e
		}
		text = value.(string)
	}
	return text + "\n" + optionalLossExplanation(r.optionalLossStatusLocked()), nil
}

// requiredLogExplanationOwned は原本を非変更で検査し、対象期間のUTC日を確認済み/未確認に分ける。
// 空日/初回固定前の消失と、保存先全体の同時巻戻りを欠落ゼロと表示しない。
func (r *Repository) requiredLogExplanationOwned(b *postingBoard, scope disclosure.Scope) string {
	from := time.Unix(0, int64(scope.From)).UTC()
	to := time.Unix(0, int64(scope.To)-1).UTC()
	start := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC)
	end := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.UTC)
	days := int(end.Sub(start)/(24*time.Hour)) + 1
	checked, gaps := 0, 0
	for rowKey, row := range b.control.State().Rows {
		day, ok := strings.CutPrefix(rowKey, "evidence_checkpoint:")
		if !ok {
			continue
		}
		at, e := time.Parse("20060102", day)
		if e != nil || at.Before(start) || at.After(end) {
			continue
		}
		if r.requiredCheckpointSourceMatches(b, day, row.Value) {
			checked++
		} else {
			gaps++
		}
	}
	return fmt.Sprintf("必須投稿ログ：対象期間のUTC日 %d日／板の固定した署名境界を原本へ照合 %d日／固定境界の欠落・照合失敗 %d日／未固定・未確認 %d日。日末境界は確認したprefixまでで、後続記録や期間内の全要求の完全性を証明しません。原本と板管理データを同時に巻き戻した状態は検出できません。", days, checked, gaps, max(0, days-checked-gaps))
}

// requiredCheckpointSourceMatches は本文/接続情報を説明へ出さず、署名と原本の現存を照合する。
func (r *Repository) requiredCheckpointSourceMatches(b *postingBoard, day string, raw []byte) bool {
	event, p, e := decodeRequiredCheckpointAnchor(day, raw)
	if e != nil || p.Owner != b.owner || domain.Time(time.Now().UnixNano()) < p.At {
		return false
	}
	if _, e = evidence.VerifyJournalCheckpoint(event, b.key.Public().(ed25519.PublicKey)); e != nil {
		return false
	}
	return inspectRequiredCheckpointSource(r.cfg, b.owner, day, event, p, b.key) == nil
}

// optionalLossExplanation は最後の同期集計と未確認期間を説明する。案件件数には読み替えない。
func optionalLossExplanation(status OptionalLossStatus) string {
	if !status.HasSnapshot || status.Summary == nil {
		return "非必須HTTPログ：同期済み欠測集計がなく未確認です。"
	}
	v := status.Summary
	k := status.Known
	text := fmt.Sprintf("非必須HTTPログ：サイト全体の累積同期集計（案件単位の件数ではありません）。確認時刻 %s／保存失敗 %d／容量拒否 %d／無効要求 %d／終了後拒否 %d／終了時破棄 %d／再起動時破棄 %d。", formatOptionalLossInstant(v.Observed), k.Failed, k.Capacity, k.Invalid, k.Closed, k.Shutdown, k.StartupDiscarded)
	if v.UnknownFrom > 0 {
		text += " 未確認期間 " + status.UnknownRange + "。この期間の欠測件数は不明です。"
	}
	if status.PersistFailed {
		text += " 現在の集計保存に失敗しており、同期以降の件数は未確認です。"
	}
	return text + " 集計観測範囲外と最終同期以降の完全性は未確認です。"
}
