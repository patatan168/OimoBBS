// 間隔の空いた返信だけ収集待ちを省き、混雑・遅い同期・時計逆行では従来の予算を維持する。
package bootstrap

import (
	"oimobbs/internal/board"
	"testing"
	"time"
)

func TestPostingCollectionIdleWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	var c postingCollection
	if got := c.startWindow(now, 0); got != 16*time.Millisecond {
		t.Fatal("initial", got)
	}
	c.saved(now, time.Millisecond)
	if got := c.startWindow(now.Add(100*time.Millisecond-time.Nanosecond), 0); got != 16*time.Millisecond {
		t.Fatal("gap below boundary", got)
	}
	if got := c.startWindow(now.Add(100*time.Millisecond), 0); got != 0 {
		t.Fatal("idle reply still waits", got)
	}
	// フォーム表示とCookie確認で操作数が増えても、最後の保存時刻は動かさない。
	c.note(now.Add(120*time.Millisecond), 1)
	if got := c.startWindow(now.Add(121*time.Millisecond), 0); got != 0 {
		t.Fatal("form lookup reset idle gap", got)
	}
	if got := c.startWindow(now.Add(-time.Nanosecond), 0); got != 16*time.Millisecond {
		t.Fatal("backwards clock", got)
	}
}

func TestPostingCollectionIdleKeepsBusyAndSlowSyncWindows(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, slow := range []bool{false, true} {
		var c postingCollection
		c.saved(now, time.Millisecond)
		c.note(now, 96)
		want := 2 * time.Millisecond
		if slow {
			c.saved(now, 8*time.Millisecond)
			want = 16 * time.Millisecond
		}
		if got := c.startWindow(now.Add(100*time.Millisecond), 0); got != want {
			t.Fatal("pressure window", slow, got)
		}
		if got := c.startWindow(now.Add(500*time.Millisecond), 0); got != 0 {
			t.Fatal("expired pressure retained wait", slow, got)
		}
	}
}

func TestPostingCollectionIdleDoesNotWaitForAbsentPeers(t *testing.T) {
	now := time.Unix(1000, 0)
	var c postingCollection
	c.saved(now, 8*time.Millisecond)
	if got := c.startWindow(now.Add(100*time.Millisecond), 0); got != 0 {
		t.Fatal("solo reply waited for absent peers", got)
	}
	if got := c.startWindow(now.Add(100*time.Millisecond), 1); got != 16*time.Millisecond {
		t.Fatal("queued peers lost slow-sync coalescing", got)
	}
}

// TestPostingCollectionKeepsChosenBudget は非idle群で従来の選択済み予算を再計算しない。
func TestPostingCollectionKeepsChosenBudget(t *testing.T) {
	for _, chosen := range []time.Duration{2 * time.Millisecond, 16 * time.Millisecond} {
		b := &postingBoard{postBatch: &board.Batch{CollectWindow: chosen}}
		b.collection.saved(time.Now(), time.Millisecond)
		if got := b.postingCollectionWindow(1); got != chosen {
			t.Fatal("changed queued budget", chosen, got)
		}
		b.collection.note(time.Now(), 96)
		if got := b.postingCollectionWindow(0); got != chosen {
			t.Fatal("changed busy budget", chosen, got)
		}
	}
}
