// 稼働中の生成数変更・取消・キャッシュ縮小を明示的な同期点で検証する。
package compat

import (
	"context"
	"errors"
	"testing"
)

func TestCompressionConfigureWhileBuilding(t *testing.T) {
	c := NewCompressionCache(1<<20, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := c.Render(t.Context(), "first", func() ([]byte, error) { close(entered); <-release; return []byte("first"), nil })
		done <- e
	}()
	<-entered
	c.Configure(0, 2)
	result, e := c.Render(t.Context(), "second", func() ([]byte, error) { return []byte("second"), nil })
	if e != nil || string(result) != "second" {
		t.Fatal("increased concurrency", e)
	}
	c.Configure(0, 1)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, e = c.Render(ctx, "cancelled", func() ([]byte, error) { t.Error("cancelled work ran"); return nil, nil })
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if s := c.Status(); s.Pending != 0 || s.Workers != 1 || s.Used != 0 || s.Entries != 0 {
		t.Fatal(s)
	}
	c.Configure(4096, 1)
	if _, e = c.Render(t.Context(), "cached", func() ([]byte, error) { return []byte("cached"), nil }); e != nil {
		t.Fatal(e)
	}
	if c.Status().Used == 0 {
		t.Fatal("cache not restored")
	}
	c.Configure(0, 1)
	if s := c.Status(); s.Used != 0 || s.Entries != 0 {
		t.Fatal("eviction", s)
	}
}
