// メモリ逼迫時の縮小・生成停止・実行中処理の完了と回復を検証する。
package compat

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func TestCompressionAdaptivePressureAndRecovery(t *testing.T) {
	cache := NewCompressionCache(0, 1)
	var pressure atomic.Bool
	cache.SetResources(func() (uint64, int) {
		if pressure.Load() {
			return 0, 0
		}
		return 4 << 20, 32
	})
	// 小さな表現を多数保持しても、1024件という固定上限で追い出さない。
	for i := range 2048 {
		_, err := cache.Render(t.Context(), fmt.Sprint(i), func() ([]byte, error) { return []byte("public"), nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	if s := cache.Status(); s.Entries != 2048 || s.Workers != 32 {
		t.Fatal(s)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := cache.Render(t.Context(), "in-flight", func() ([]byte, error) { close(entered); <-release; return []byte("finished"), nil })
		done <- err
	}()
	<-entered
	pressure.Store(true)
	cache.RefreshResources()
	if s := cache.Status(); s.Used != 0 || s.Entries != 0 || s.Workers != 0 {
		t.Fatal("pressure not applied", s)
	}
	if _, err := cache.Render(t.Context(), "new", func() ([]byte, error) { t.Error("work started during pressure"); return nil, nil }); !errors.Is(err, ErrCompressionCapacity) {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal("in-flight discarded", err)
	}
	if s := cache.Status(); s.Used != 0 || s.Pending != 0 {
		t.Fatal("pressure retained output", s)
	}
	pressure.Store(false)
	cache.RefreshResources()
	if _, err := cache.Render(t.Context(), "recovered", func() ([]byte, error) { return []byte("ok"), nil }); err != nil {
		t.Fatal(err)
	}
	if s := cache.Status(); s.Entries != 1 || s.Workers != 32 {
		t.Fatal("did not recover", s)
	}
}

func TestCompressionMemoryAdmission(t *testing.T) {
	cache := NewCompressionCache(1024, 1)
	cache.SetAdmission(func() (func(), bool) { return nil, false })
	if _, err := cache.Render(t.Context(), "denied", func() ([]byte, error) { t.Error("unreserved work"); return nil, nil }); !errors.Is(err, ErrCompressionCapacity) {
		t.Fatal(err)
	}
	released := 0
	cache.SetAdmission(func() (func(), bool) { return func() { released++ }, true })
	if _, err := cache.Render(t.Context(), "accepted", func() ([]byte, error) { return []byte("ok"), nil }); err != nil || released != 1 {
		t.Fatal(err, released)
	}
}

func TestCompressionAdaptiveManyIndependentBuilds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := NewCompressionCache(0, 1)
		cache.SetResources(func() (uint64, int) { return 0, 32 })
		started := make(chan struct{}, 32)
		release := make(chan struct{})
		var group sync.WaitGroup
		defer func() { close(release); group.Wait() }()
		for index := range 32 {
			group.Go(func() {
				_, err := cache.Render(t.Context(), fmt.Sprint(index), func() ([]byte, error) { started <- struct{}{}; <-release; return nil, nil })
				if err != nil {
					t.Error(err)
				}
			})
		}
		synctest.Wait()
		if len(started) != 32 {
			t.Fatal("many-core work serialized", len(started))
		}
	})
}
