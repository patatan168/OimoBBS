// 回線分類の間隔・毎日・毎週・毎月の予定を、日本時間の暦に従って計算する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"slices"
	"time"
)

const networkScheduleReader uint32 = 108

// NetworkSchedule は時刻指定更新の保存値。StartsAtは設定保存時にサーバーが確定する。
// Weekdayは日曜0〜土曜6。Dayは1〜31、0は月末で、存在しない日はその月の末日にする。
type NetworkSchedule struct {
	Frequency string      `json:"frequency"`
	Time      string      `json:"time"`
	Weekday   uint32      `json:"weekday"`
	Day       uint32      `json:"day"`
	StartsAt  domain.Time `json:"starts_at_ns"`
}

// validNetworkUpdateAt はHH:MMの正規表記だけを許可する。
func validNetworkUpdateAt(value string) bool {
	at, err := time.Parse("15:04", value)
	return err == nil && at.Format("15:04") == value
}

// validNetworkSchedule は入力の暦条件を検査する。開始日時0は保存前の入力に限って使う。
func validNetworkSchedule(v *NetworkSchedule) bool {
	return v == nil || slices.Contains([]string{"daily", "weekly", "monthly"}, v.Frequency) && validNetworkUpdateAt(v.Time) && v.Weekday <= 6 && v.Day <= 31 && v.StartsAt >= 0
}

// nextNetworkUpdate は次の開始予定を返す。過去の予定は取得待ち、ゼロ値は停止・取得元なし。
func nextNetworkUpdate(v networkState, now time.Time) time.Time {
	if !v.Config.Enabled || len(v.Config.Sources) == 0 {
		return time.Time{}
	}
	if schedule := v.Config.Schedule; schedule != nil {
		reference := now.In(domain.JST)
		start, last := time.Unix(0, int64(schedule.StartsAt)), time.Unix(0, int64(v.LastAttempt))
		if reference.Before(start) {
			reference = start.In(domain.JST)
		}
		if reference.Before(last) {
			reference = last.In(domain.JST)
		}
		slot := networkScheduleSlot(*schedule, reference, 0)
		if slot.Before(start) || !slot.After(last) {
			slot = networkScheduleSlot(*schedule, reference, 1)
		}
		return slot
	}
	if v.LastAttempt == 0 || v.AttemptVersion != v.Version {
		return now
	}
	interval := time.Duration(v.Config.IntervalHours) * time.Hour
	if v.Error != "" {
		interval = time.Hour
	}
	return time.Unix(0, int64(v.LastAttempt)).Add(interval)
}

// networkScheduleSlot は基準日の属する期間、または次の期間の予定を計算する。
func networkScheduleSlot(v NetworkSchedule, reference time.Time, next int) time.Time {
	reference = reference.In(domain.JST)
	at, _ := time.Parse("15:04", v.Time)
	year, month, day := reference.Date()
	switch v.Frequency {
	case "daily":
		day += next
	case "weekly":
		day += int(v.Weekday) - int(reference.Weekday()) + next*7
	case "monthly":
		month += time.Month(next)
		last := time.Date(year, month+1, 0, 0, 0, 0, 0, domain.JST).Day()
		day = int(v.Day)
		if day == 0 || day > last {
			day = last
		}
	}
	return time.Date(year, month, day, at.Hour(), at.Minute(), 0, 0, domain.JST)
}

// withLegacyNetworkSchedule は旧設定だけに未指定の予定を補い、他の必須項目や重複キーを緩めない。
func withLegacyNetworkSchedule(raw []byte) []byte {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return raw
	}
	if _, ok := fields["schedule"]; ok {
		return raw
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '{' {
		return raw
	}
	return append([]byte(`{"schedule":null,`), raw[1:]...)
}

// savedNetworkSchedule は入力の開始日時を採用せず、規則を変えた保存時だけ開始日時を確定する。
func savedNetworkSchedule(input, previous *NetworkSchedule, now domain.Time) *NetworkSchedule {
	if input == nil {
		return nil
	}
	next := *input
	next.StartsAt = 0
	if previous != nil {
		old := *previous
		old.StartsAt = 0
		if old == next {
			next.StartsAt = previous.StartsAt
			return &next
		}
	}
	next.StartsAt = now
	return &next
}
