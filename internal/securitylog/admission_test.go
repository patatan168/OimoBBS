// 投稿優先の背景保存が表示・終了・逼迫・期限・保存失敗で滞留しないことを検査する。
package securitylog

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionControlWakesWriter(t *testing.T) {
	for _, closeLog := range []bool{false, true} {
		t.Run(map[bool]string{false: "view", true: "close"}[closeLog], func(t *testing.T) {
			entered, urgent := make(chan struct{}), make(chan struct{})
			var first atomic.Bool
			l, err := OpenWithAdmission(t.TempDir(), func(ctx context.Context, pressure func() bool, wake <-chan struct{}) (func(), error) {
				if first.CompareAndSwap(false, true) {
					close(entered)
					for !pressure() {
						select {
						case <-wake:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					close(urgent)
				}
				return func() {}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			now := time.Now()
			l.Add(Event{At: now, Source: "waf", Reason: "traffic_limit", Rejected: true})
			<-entered
			done := make(chan error, 1)
			go func() {
				if closeLog {
					done <- l.Close()
				} else {
					v, e := l.View(now)
					if e == nil && v.Rejected != 1 {
						t.Error(v.Rejected)
					}
					done <- e
				}
			}()
			select {
			case <-urgent:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("表示・終了が優先待ちを解除しなかった")
			}
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("保存が完了しない")
			}
		})
	}
}

func TestAdmissionBacklogKeepsAllCounts(t *testing.T) {
	entered, resumed := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	l, err := OpenWithAdmission(t.TempDir(), func(ctx context.Context, pressure func() bool, wake <-chan struct{}) (func(), error) {
		if first.CompareAndSwap(false, true) {
			close(entered)
			for !pressure() {
				select {
				case <-wake:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			close(resumed)
		}
		return func() {}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now()
	event := Event{At: now, Source: "waf", Reason: "traffic_limit", Rejected: true}
	l.Add(event)
	<-entered
	for range 300 {
		l.Add(event)
	}
	select {
	case <-resumed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("逼迫通知が保存を再開しなかった")
	}
	v, e := l.View(now)
	if e != nil || v.Rejected != 301 {
		t.Fatal(v.Rejected, e)
	}
}

func TestAdmissionDeadlineStillSaves(t *testing.T) {
	var calls atomic.Int64
	dir := t.TempDir()
	l, err := OpenWithAdmission(dir, func(ctx context.Context, pressure func() bool, wake <-chan struct{}) (func(), error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if !pressure() {
			t.Error("期限後に進行条件を強めなかった")
		}
		return func() {}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.Add(Event{At: now, Source: "waf", Rejected: true})
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2 {
		t.Fatal("期限後に保存しなかった")
	}
	rows, e := load(filepath.Join(dir, bucket(Event{At: now})+".json"))
	if e != nil || len(rows) != 1 {
		t.Fatal("期限後の保存がない", rows, e)
	}
}

func TestAdmissionReleasesOnSnapshotFailure(t *testing.T) {
	var active atomic.Int64
	dir := t.TempDir()
	now := time.Now()
	if err := os.Mkdir(filepath.Join(dir, bucket(Event{At: now})+".json"), 0700); err != nil {
		t.Fatal(err)
	}
	l, err := OpenWithAdmission(dir, func(context.Context, func() bool, <-chan struct{}) (func(), error) {
		active.Add(1)
		return func() { active.Add(-1) }, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	l.Add(Event{At: now, Source: "waf"})
	v, e := l.View(now)
	if e != nil || v.Error == "" || active.Load() != 0 {
		t.Fatal(v.Error, e, active.Load())
	}
	if err = l.Close(); err == nil || active.Load() != 0 {
		t.Fatal(err, active.Load())
	}
}

func TestAdmissionFailureDoesNotCacheUnsavedCounts(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	event := Event{At: now, Source: "waf", Reason: "traffic_limit", Rejected: true}
	initial, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	initial.Add(event)
	if err = initial.Close(); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	failure := context.Canceled
	l, err := OpenWithAdmission(dir, func(context.Context, func() bool, <-chan struct{}) (func(), error) {
		if calls.Add(1) == 1 {
			return nil, failure
		}
		return func() {}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	l.Add(event)
	v, e := l.View(now)
	if e != nil || v.Error == "" || v.Rejected != 1 {
		t.Fatal(v.Rejected, v.Error, e)
	}
	l.Add(event)
	v, e = l.View(now)
	if e != nil || v.Error == "" || v.Rejected != 2 {
		t.Fatal("未保存の件数を再利用した", v.Rejected, v.Error, e)
	}
	if err = l.Close(); err == nil {
		t.Fatal("優先枠取得の失敗を消した")
	}
}
