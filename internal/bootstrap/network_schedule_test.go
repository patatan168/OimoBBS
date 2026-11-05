// 日本時間の指定時刻・間隔・停止・手動取得による次回予定を、時計待ちなしで検証する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"testing"
	"time"
)

// TestNetworkDailySchedule は保存・起動前後も当日の指定時刻を境界に一度だけ取得する。
func TestNetworkDailySchedule(t *testing.T) {
	at := func(day, hour, minute int) time.Time { return time.Date(2026, 11, day, hour, minute, 0, 0, domain.JST) }
	for _, tc := range []struct {
		name                string
		now, previous, want time.Time
	}{
		{"before_first", at(5, 3, 59), time.Time{}, at(5, 4, 0)},
		{"at_first", at(5, 4, 0), time.Time{}, at(5, 4, 0)},
		{"missed_on_restart", at(5, 9, 0), at(4, 4, 0), at(5, 4, 0)},
		{"already_attempted", at(5, 4, 1), at(5, 4, 0), at(6, 4, 0)},
		{"manual_before_slot", at(5, 3, 0), at(5, 2, 0), at(5, 4, 0)},
		{"manual_after_slot", at(5, 9, 0), at(5, 8, 0), at(6, 4, 0)},
		{"clock_rollback", at(5, 3, 0), at(6, 5, 0), at(7, 4, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := networkState{Config: NetworkConfig{Enabled: true, Schedule: &NetworkSchedule{Frequency: "daily", Time: "04:00", StartsAt: domain.Time(at(1, 0, 0).UnixNano())}, IntervalHours: 24, Sources: []NetworkSource{{Type: "asn"}}}}
			if !tc.previous.IsZero() {
				v.LastAttempt = domain.Time(tc.previous.UnixNano())
			}
			if got := nextNetworkUpdate(v, tc.now.UTC()); !got.Equal(tc.want) {
				t.Fatal(got, tc.want)
			}
			v.Error = "fetch_failed"
			if got := nextNetworkUpdate(v, tc.now.UTC()); !got.Equal(tc.want) {
				t.Fatal("failure shifted daily slot", got)
			}
		})
	}
}

// TestNetworkScheduleValidation は分単位の正規時刻だけを受け入れる。
func TestNetworkScheduleValidation(t *testing.T) {
	for _, value := range []string{"00:00", "04:00", "23:59"} {
		if !validNetworkUpdateAt(value) {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"", "4:00", "24:00", "04:60", "04:00:00", "04:00 ", "ab:cd", "-1:00", "０４:００"} {
		if validNetworkUpdateAt(value) {
			t.Fatal(value)
		}
	}
	for _, schedule := range []NetworkSchedule{
		{Frequency: "yearly", Time: "04:00"},
		{Frequency: "weekly", Time: "04:00", Weekday: 7},
		{Frequency: "monthly", Time: "04:00", Day: 32},
		{Frequency: "daily", Time: "04:00", StartsAt: -1},
	} {
		if validNetworkSchedule(&schedule) {
			t.Fatal("invalid calendar accepted", schedule)
		}
	}
}

// TestNetworkScheduleActivation は入力の開始日時を採用せず、同じ規則の再保存では開始を延ばさない。
func TestNetworkScheduleActivation(t *testing.T) {
	input := &NetworkSchedule{Frequency: "daily", Time: "04:00", StartsAt: 1}
	first := savedNetworkSchedule(input, nil, 10)
	if first.StartsAt != 10 || input.StartsAt != 1 {
		t.Fatal(first, input)
	}
	if got := savedNetworkSchedule(input, first, 20); got.StartsAt != 10 {
		t.Fatal("unchanged rule postponed", got)
	}
	input.Time = "05:00"
	if got := savedNetworkSchedule(input, first, 20); got.StartsAt != 20 || first.Time != "04:00" {
		t.Fatal("new rule did not activate", got, first)
	}
}

// TestNetworkCalendarSchedule は週・月・年の境界と月末への丸め、設定直後の待機を検査する。
func TestNetworkCalendarSchedule(t *testing.T) {
	parse := func(v string) time.Time {
		at, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	for _, tc := range []struct {
		name, frequency, now, start, last, want string
		weekday, day                            uint32
	}{
		{"weekly_before", "weekly", "2026-11-05T03:00:00+09:00", "2026-11-01T00:00:00+09:00", "", "2026-11-05T04:00:00+09:00", 4, 1},
		{"weekly_new", "weekly", "2026-11-05T10:00:00+09:00", "2026-11-05T10:00:00+09:00", "", "2026-11-09T04:00:00+09:00", 1, 1},
		{"weekly_done", "weekly", "2026-11-05T10:00:00+09:00", "2026-11-01T00:00:00+09:00", "2026-11-05T04:01:00+09:00", "2026-11-12T04:00:00+09:00", 4, 1},
		{"month_31", "monthly", "2026-11-05T10:00:00+09:00", "2026-11-01T00:00:00+09:00", "", "2026-11-30T04:00:00+09:00", 0, 31},
		{"month_end", "monthly", "2026-02-15T10:00:00+09:00", "2026-02-01T00:00:00+09:00", "", "2026-02-28T04:00:00+09:00", 0, 0},
		{"leap_month", "monthly", "2028-02-15T10:00:00+09:00", "2028-02-01T00:00:00+09:00", "", "2028-02-29T04:00:00+09:00", 0, 31},
		{"next_year", "monthly", "2026-12-31T10:00:00+09:00", "2026-12-01T00:00:00+09:00", "2026-12-31T04:00:00+09:00", "2027-01-31T04:00:00+09:00", 0, 31},
		{"daily_new", "daily", "2026-11-05T10:00:00+09:00", "2026-11-05T10:00:00+09:00", "", "2026-11-06T04:00:00+09:00", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := networkState{Config: NetworkConfig{Enabled: true, Schedule: &NetworkSchedule{Frequency: tc.frequency, Time: "04:00", Weekday: tc.weekday, Day: tc.day, StartsAt: domain.Time(parse(tc.start).UnixNano())}, Sources: []NetworkSource{{Type: "asn"}}}}
			if tc.last != "" {
				v.LastAttempt = domain.Time(parse(tc.last).UnixNano())
			}
			if got := nextNetworkUpdate(v, parse(tc.now).UTC()); !got.Equal(parse(tc.want)) {
				t.Fatal(got, tc.want)
			}
			v.Config.Enabled = false
			if !nextNetworkUpdate(v, parse(tc.now)).IsZero() {
				t.Fatal("stopped schedule active")
			}
		})
	}
}
