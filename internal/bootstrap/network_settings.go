// 回線分類の更新設定を通常フォームへ表示し、時刻・曜日・日付を厳密に受け取る。
package bootstrap

import (
	"fmt"
	"net/url"
	"oimobbs/internal/domain"
	"strconv"
	"time"
)

type networkScheduleOption struct{ Value, Label string }

// networkFormSchedule は間隔指定をnilへ、暦指定を保存前の予定へ変換する。
func networkFormSchedule(fields url.Values) (*NetworkSchedule, error) {
	if fields.Get("schedule_mode") == "interval" {
		return nil, nil
	}
	v := &NetworkSchedule{Frequency: fields.Get("schedule_mode"), Time: fields.Get("schedule_time")}
	for _, field := range []struct {
		mode, name string
		value      *uint32
	}{{"weekly", "schedule_weekday", &v.Weekday}, {"monthly", "schedule_day", &v.Day}} {
		if v.Frequency != field.mode {
			continue
		}
		value, err := strconv.ParseUint(fields.Get(field.name), 10, 32)
		if err != nil {
			return nil, errNetworkData
		}
		*field.value = uint32(value)
	}
	if !validNetworkSchedule(v) {
		return nil, errNetworkData
	}
	return v, nil
}

// ScheduleField は保存失敗時の入力を優先し、未設定の時刻入力には04:00を表示する。
func (p networksPage) ScheduleField(name string) string {
	if p.Fields.Get("action") == "settings" && p.Fields.Has(name) {
		return p.Fields.Get(name)
	}
	v := p.View.Config.Schedule
	switch name {
	case "schedule_mode":
		if v != nil {
			return v.Frequency
		}
		return "interval"
	case "schedule_time":
		if v != nil {
			return v.Time
		}
		return "04:00"
	case "schedule_weekday":
		if v != nil {
			return strconv.Itoa(int(v.Weekday))
		}
		return "1"
	case "schedule_day":
		if v != nil {
			return strconv.Itoa(int(v.Day))
		}
		return "1"
	case "enabled":
		return strconv.FormatBool(p.View.Config.Enabled)
	case "interval_hours":
		return strconv.Itoa(int(p.View.Config.IntervalHours))
	case "dns_mode":
		return p.View.Config.DNSMode
	}
	return ""
}

// ScheduleWeekdays は日本語の曜日を、保存する0〜6の値に対応させる。
func (p networksPage) ScheduleWeekdays() []networkScheduleOption {
	rows := []networkScheduleOption{}
	for i, day := range []string{"日曜日", "月曜日", "火曜日", "水曜日", "木曜日", "金曜日", "土曜日"} {
		rows = append(rows, networkScheduleOption{strconv.Itoa(i), day})
	}
	return rows
}

// ScheduleDays は月末を含む日付候補を返す。31日のない月の繰越は予定計算で月末へ丸める。
func (p networksPage) ScheduleDays() []networkScheduleOption {
	rows := []networkScheduleOption{{"0", "月末"}}
	for day := 1; day <= 31; day++ {
		rows = append(rows, networkScheduleOption{strconv.Itoa(day), fmt.Sprintf("%d日", day)})
	}
	return rows
}

// UpdatePlan は保存中の更新方式を、時刻の解釈を含めて表示する。
func (p networksPage) UpdatePlan() string {
	if !p.View.Config.Enabled {
		return "停止中"
	}
	v := p.View.Config.Schedule
	if v == nil {
		return fmt.Sprintf("%d時間ごと", p.View.Config.IntervalHours)
	}
	prefix := "毎日"
	if v.Frequency == "weekly" {
		prefix = "毎週" + []string{"日曜", "月曜", "火曜", "水曜", "木曜", "金曜", "土曜"}[v.Weekday]
	}
	if v.Frequency == "monthly" {
		prefix = fmt.Sprintf("毎月%d日", v.Day)
		if v.Day == 0 {
			prefix = "毎月末"
		}
	}
	return prefix + " " + v.Time + "（日本時間）"
}

// DisplayNetworkTime はAPIの時刻表現を変えず、画面だけを読みやすい日本時間へ整える。
func (p networksPage) DisplayNetworkTime(raw string) string {
	if raw == "" {
		return "—"
	}
	v, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return raw
	}
	return v.In(domain.JST).Format("2006/01/02 15:04")
}
