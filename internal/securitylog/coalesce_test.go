// 検出イベントの有限収集、表示・終了による打切りと保存境界を検査する。
package securitylog

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestCollectSecurityBatchWaitsForWindowOrControl(t *testing.T) {
	for _, control := range []string{"window", "barrier", "stop"} {
		t.Run(control, func(t *testing.T) {
			input := make(chan message)
			elapsed := make(chan time.Time)
			done := make(chan []message, 1)
			first := message{event: &Event{Source: "waf"}}
			go func() { done <- collectSecurityBatch(first, input, elapsed) }()
			// unbuffered受信で、間隔を空けて到着する次の一件も同じ群へ入ったと同期する。
			input <- message{event: &Event{Source: "similar"}}
			select {
			case <-done:
				t.Fatal("収集期限前に別の保存へ分割した")
			default:
			}
			switch control {
			case "window":
				elapsed <- time.Now()
			case "barrier":
				input <- message{barrier: make(chan error, 1)}
			case "stop":
				input <- message{stop: true}
			}
			select {
			case batch := <-done:
				want := 2
				if control != "window" {
					want = 3
				}
				if len(batch) != want {
					t.Fatal(len(batch), want)
				}
			case <-time.After(time.Second):
				t.Fatal("期限・表示・終了で収集を打ち切れない")
			}
		})
	}
}

func TestCollectSecurityBatchFullAndInitialControl(t *testing.T) {
	input := make(chan message, 256)
	for range 256 {
		input <- message{event: &Event{Source: "waf"}}
	}
	done := make(chan []message, 1)
	go func() { done <- collectSecurityBatch(message{event: &Event{}}, input, nil) }()
	select {
	case batch := <-done:
		if len(batch) != 256 || len(input) != 1 {
			t.Fatal(len(batch), len(input))
		}
	case <-time.After(time.Second):
		t.Fatal("満杯の群が収集期限を待った")
	}
	for _, first := range []message{{barrier: make(chan error, 1)}, {stop: true}} {
		batch := collectSecurityBatch(first, input, nil)
		if len(batch) != 1 || len(input) != 1 {
			t.Fatal("先頭の表示・終了通知で後続を消費した", len(batch), len(input))
		}
	}
}

func TestCollectSecurityBatchPreservesBarrierBoundary(t *testing.T) {
	input := make(chan message, 3)
	barrier := make(chan error, 1)
	input <- message{event: &Event{Source: "second"}}
	input <- message{barrier: barrier}
	input <- message{event: &Event{Source: "after_barrier"}}
	batch := collectSecurityBatch(message{event: &Event{Source: "first"}}, input, nil)
	if len(batch) != 3 || batch[2].barrier != barrier || len(input) != 1 {
		t.Fatal("表示境界を越えた", len(batch), len(input))
	}
	close(input)
	if got := collectSecurityBatch(<-input, input, nil); len(got) != 1 {
		t.Fatal("閉じた入力で待機した", len(got))
	}
}

func TestLargeSnapshotCoalescingScope(t *testing.T) {
	now := time.Now()
	file, err := os.CreateTemp(t.TempDir(), "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = file.Truncate(64 << 10); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	cache := bucketRows{name: bucket(Event{At: now}), info: info}
	l := &Log{queue: make(chan message, 256), wake: make(chan struct{}, 1), admission: func(context.Context, func() bool, <-chan struct{}) (func(), error) { return func() {}, nil }}
	first := message{event: &Event{At: now}}
	if !l.coalesces(first, &cache) {
		t.Fatal("大きいsnapshotをまとめない")
	}
	done := l.requireFlush()
	if l.coalesces(first, &cache) {
		t.Fatal("表示・終了の保存を収集待ちにした")
	}
	done()
	cache.name = bucket(Event{At: now.Add(-time.Hour)})
	if l.coalesces(first, &cache) {
		t.Fatal("別時間帯を遅延した")
	}
	cache.name = bucket(Event{At: now})
	for range admissionBacklog {
		l.queue <- message{event: &Event{At: now}}
	}
	if l.coalesces(first, &cache) {
		t.Fatal("受付列の逼迫を遅延した")
	}
	for len(l.queue) > 0 {
		<-l.queue
	}
	if l.coalesces(message{barrier: make(chan error, 1)}, &cache) {
		t.Fatal("表示を遅延した")
	}
	l.admission = nil
	if l.coalesces(first, &cache) {
		t.Fatal("従来のOpenへ収集待ちを追加した")
	}
}
