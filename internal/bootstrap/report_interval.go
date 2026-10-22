// 削除依頼の送信間隔と、旧保存形式の限定的な既定値補完を扱う。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"time"

	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
)

const reportIntervalReader = 100

// decodeReportDefault は追加した1項目だけを補完し、未知・重複・他の欠落項目は拒否する。
func decodeReportDefault(raw []byte, dst any, name, fallback string) error {
	fields, err := strictjson.SelectFields(raw, name)
	if err != nil {
		return err
	}
	if fields[name] != nil {
		return strictjson.Decode(raw, dst)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return err
	}
	all[name] = json.RawMessage(fallback)
	normalized, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return strictjson.Decode(normalized, dst)
}

// UnmarshalJSON は旧運用設定の省略だけを既定値として読み込む。
func (v *OperationSettings) UnmarshalJSON(raw []byte) error {
	type wire OperationSettings
	return decodeReportDefault(raw, (*wire)(v), "report_interval_minutes", "0")
}

// UnmarshalJSON は既存APIクライアントの送信間隔省略を許可する。
func (v *editableOperationSettings) UnmarshalJSON(raw []byte) error {
	type wire editableOperationSettings
	return decodeReportDefault(raw, (*wire)(v), "report_interval_minutes", "0")
}

// UnmarshalJSON は旧依頼に識別hashがない場合だけnullを補完する。
func (v *deletionReport) UnmarshalJSON(raw []byte) error {
	type wire deletionReport
	return decodeReportDefault(raw, (*wire)(v), "reporter_hash", "null")
}

func reportActorHash(key [32]byte, cookie string) domain.Hash {
	return identity.MAC(key[:], "oimo/report-actor/v1", []byte(cookie))
}

// reportSubmissionRate は確定済み依頼を使い、再起動・Cookie再発行でも回線上限を保つ。
// 呼出元はサイトと依頼のmutexを保持する。自動通報は件数に数えない。
func (repo *Repository) reportSubmissionRate(ids []domain.ID, v deletionReport, key [32]byte, now time.Time) error {
	interval := time.Duration(repo.operations().reportIntervalMinutes()) * time.Minute
	cutoff := domain.Time(now.Add(-interval).UnixNano())
	var latest domain.Time
	var networkTimes []domain.Time
	for _, id := range ids {
		prior, err := readReport(repo.cfg.DataDir, id, key)
		if err != nil {
			return err
		}
		if prior.Created > domain.Time(now.UnixNano()) {
			return abuse.ErrRateClock
		}
		if prior.Automatic != nil || prior.Created <= cutoff {
			continue
		}
		if prior.ReporterHash != nil && v.ReporterHash != nil && *prior.ReporterHash == *v.ReporterHash {
			latest = max(latest, prior.Created)
		}
		if prior.SourceIP == v.SourceIP {
			networkTimes = append(networkTimes, prior.Created)
		}
	}
	if len(networkTimes) >= 3 {
		slices.Sort(networkTimes)
		latest = max(latest, networkTimes[len(networkTimes)-3])
	}
	if latest == 0 {
		return nil
	}
	remaining := time.Unix(0, int64(latest)).Add(interval).Sub(now)
	return &abuse.RateLimited{RetryAfter: uint64((remaining + time.Second - 1) / time.Second)}
}

// writeReportRateError は待ち時間と入力内容を表示し、照会フォームを引き続き使えるようにする。
func writeReportRateError(w http.ResponseWriter, page reportsPage, err error) {
	seconds := uint64(60)
	if limited, ok := err.(*abuse.RateLimited); ok {
		seconds = limited.RetryAfter
	}
	w.Header().Set("Retry-After", strconv.FormatUint(seconds, 10))
	page.Message = "連続した依頼を制限しています。あと約" + strconv.FormatUint((seconds+59)/60, 10) + "分待ってから送信してください。受付済み依頼の照会は利用できます。"
	writeReportsPage(w, 429, page)
}
