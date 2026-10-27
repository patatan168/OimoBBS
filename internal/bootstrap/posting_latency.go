// 有界の投稿時間窓から保守圧縮の一時停止・再開を判断する。
package bootstrap

import (
	"oimobbs/internal/store"
	"sort"
	"time"
)

const latencySampleLimit = 4096

type latencySample struct {
	at       time.Time
	duration time.Duration
}

// PostingLatencyStatus は本文や投稿者情報を持たない集計結果。
type PostingLatencyStatus struct {
	Samples    int    `json:"samples"`
	P99Millis  int64  `json:"p99_ms"`
	Known      bool   `json:"known"`
	Paused     bool   `json:"compaction_paused"`
	Recovering bool   `json:"recovering"`
	Checked    string `json:"checked"`
}
type postingLatencyState struct {
	samples                   [latencySampleLimit]latencySample
	next                      int
	overflowUntil             time.Time
	last, highSince, lowSince time.Time
	paused                    bool
}

// add は最大4096件を保持し、現行窓の標本を上書きした場合は集計不能を記録する。
func (s *postingLatencyState) add(now time.Time, d time.Duration) {
	if d < 0 {
		return
	}
	old := s.samples[s.next]
	if !old.at.IsZero() && now.Sub(old.at) < time.Minute {
		s.overflowUntil = now.Add(time.Minute)
	}
	s.samples[s.next] = latencySample{now, d}
	s.next = (s.next + 1) % latencySampleLimit
}

// observe は60秒窓のnearest-rank P99と、停止60秒・回復120秒の連続観測を扱う。
func (s *postingLatencyState) observe(now time.Time) PostingLatencyStatus {
	status := PostingLatencyStatus{Known: !now.Before(s.overflowUntil), Checked: now.UTC().Format(time.RFC3339)}
	gap := now.Sub(s.last)
	if !s.last.IsZero() && (gap < 0 || gap > 5*time.Second) {
		s.highSince = time.Time{}
		s.lowSince = time.Time{}
	}
	s.last = now
	values := make([]time.Duration, 0, latencySampleLimit)
	for _, sample := range s.samples {
		age := now.Sub(sample.at)
		if sample.at.IsZero() || age >= time.Minute {
			continue
		}
		if age < 0 {
			status.Known = false
			continue
		}
		values = append(values, sample.duration)
	}
	status.Samples = len(values)
	var p99 time.Duration
	if len(values) > 0 {
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		p99 = values[(len(values)*99+99)/100-1]
	}
	status.P99Millis = int64(p99 / time.Millisecond)
	if p99%time.Millisecond != 0 {
		status.P99Millis++
	}
	if !status.Known {
		s.paused = true
		s.highSince = time.Time{}
		s.lowSince = time.Time{}
	} else if !s.paused {
		if p99 > 250*time.Millisecond {
			if s.highSince.IsZero() {
				s.highSince = now
			}
			if now.Sub(s.highSince) >= time.Minute {
				s.paused = true
				s.lowSince = time.Time{}
			}
		} else {
			s.highSince = time.Time{}
		}
	} else if p99 < 150*time.Millisecond {
		if s.lowSince.IsZero() {
			s.lowSince = now
		}
		if now.Sub(s.lowSince) >= 2*time.Minute {
			s.paused = false
			s.highSince = time.Time{}
			s.lowSince = time.Time{}
		}
	} else {
		s.lowSince = time.Time{}
	}
	status.Paused = s.paused
	status.Recovering = s.paused && !s.lowSince.IsZero()
	return status
}

// recordPostingLatency は新規受理・結果不明の保存処理だけを記録し、再送・確認・入力拒否を除く。
func (r *Repository) recordPostingLatency(started time.Time, result RepositoryPostingResult) {
	if result.Duplicate || (result.Status != store.Durable && result.Status != store.Unknown) {
		return
	}
	r.postingLatencyMu.Lock()
	defer r.postingLatencyMu.Unlock()
	now := time.Now()
	r.postingLatency.add(now, now.Sub(started))
}

// PostingLatency は直近60秒の集計と圧縮の延期状態を返す。投稿受付自体を停止しない。
func (r *Repository) PostingLatency() PostingLatencyStatus {
	r.postingLatencyMu.Lock()
	defer r.postingLatencyMu.Unlock()
	now := time.Now()
	if r.latencyClock != nil {
		now = r.latencyClock()
	}
	return r.postingLatency.observe(now)
}
