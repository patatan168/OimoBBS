// 長期窓の待ち秒と予約票の分離を旧計算へ照合し、制限条件を維持した費用を測る。
package abuse

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// referenceWindowWait は変更前の全窓走査を、待機秒の比較基準として残す。
func referenceWindowWait(b *rateBucket, now time.Time, cost uint32) (uint64, error) {
	debit := uint64(cost) * uint64(b.spec.Every)
	wait := uint64(0)
	if b.credit < debit {
		wait = ceilRate(ceilRate(debit-b.credit, b.spec.Tokens), uint64(time.Second))
	}
	if b.spec.WindowLimit == 0 {
		return wait, nil
	}
	if uint64(cost)+b.pending > uint64(b.spec.WindowLimit) {
		return 0, ErrRateUncertain
	}
	minute := now.Unix() / 60
	for offset := int64(0); offset <= 61; offset++ {
		if b.count(minute+offset)+uint64(cost) <= uint64(b.spec.WindowLimit) {
			if offset > 0 {
				wait = max(wait, uint64((minute+offset)*60-now.Unix()))
			}
			return wait, nil
		}
	}
	return 0, ErrRateUncertain
}

func FuzzLimiterWindowWait(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, uint8(6), uint8(1), uint8(59))
	f.Add([]byte{255, 255, 255}, uint8(1), uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, history []byte, limit, pending, second uint8) {
		b := rateBucket{spec: RateSpec{Tokens: 3, Every: time.Second, Burst: 100, WindowLimit: uint32(limit) + 1}, pending: uint64(pending), minutes: new([61]rateMinute)}
		for i, v := range history {
			if i == 61 {
				break
			}
			minute := int64(i) + 90
			b.minutes[minute%61] = rateMinute{minute: minute, count: uint64(v)}
		}
		now := time.Unix(120*60+int64(second%60), 0)
		want, oldErr := referenceWindowWait(&b, now, 1)
		got, err := b.wait(now, 1)
		if got != want || !errors.Is(err, oldErr) {
			t.Fatal(got, err, want, oldErr)
		}
	})
}

func TestLimiterTicketOwnsReservation(t *testing.T) {
	l := NewLimiter(1)
	now := time.Unix(1800000000, 0)
	charges := []RateCharge{{Key: "first", Spec: limitSpec(1), Cost: 1}}
	ticket, err := l.Reserve(now, charges)
	if err != nil {
		t.Fatal(err)
	}
	charges[0] = RateCharge{Key: "changed", Spec: limitSpec(100), Cost: 100}
	l.Prune(now.Add(time.Hour))
	if err := l.Release(ticket); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Reserve(now.Add(time.Hour), []RateCharge{{Key: "first", Spec: limitSpec(1), Cost: 1}}); err != nil {
		t.Fatal("入力の変更で予約が壊れた", err)
	}
}

func BenchmarkLimiterReservation(b *testing.B) {
	for _, count := range []int{1, 4, 16} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			l := NewLimiter(100)
			charges := make([]RateCharge, count)
			for i := range charges {
				charges[i] = RateCharge{Key: fmt.Sprint(i), Spec: limitSpec(100), Cost: 1}
			}
			now := time.Unix(1800000000, 0)
			b.ReportAllocs()
			for b.Loop() {
				ticket, err := l.Reserve(now, charges)
				if err != nil {
					b.Fatal(err)
				}
				if err = l.Release(ticket); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLimiterWindowRejected(b *testing.B) {
	bucket := rateBucket{spec: RateSpec{Tokens: 1, Every: time.Second, Burst: 1, WindowLimit: 1}, credit: uint64(time.Second), minutes: new([61]rateMinute)}
	bucket.minutes[120%61] = rateMinute{minute: 120, count: 1}
	now := time.Unix(120*60, 0)
	b.ReportAllocs()
	for b.Loop() {
		if wait, err := bucket.wait(now, 1); wait != 3660 || err != nil {
			b.Fatal(wait, err)
		}
	}
}
