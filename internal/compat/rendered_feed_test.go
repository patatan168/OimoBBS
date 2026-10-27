// 本文と検証子の共有が更新・容量・取消で古い応答を混ぜないことを検査する。
package compat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
)

func TestRenderedFeedETagAndLifetime(t *testing.T) {
	for _, limit := range []uint64{0, 4096} {
		cache := NewCompressionCache(limit, 1)
		calls := 0
		render := func() ([]byte, error) { calls++; return []byte("public"), nil }
		for range 2 {
			feed, err := cache.RenderFeed(t.Context(), "version-1", render)
			sum := sha256.Sum256([]byte("public"))
			if err != nil || !bytes.Equal(feed.Body, []byte("public")) || feed.Tag != "feed-"+base64.RawURLEncoding.EncodeToString(sum[:]) {
				t.Fatal(feed, err)
			}
		}
		wantCalls := 1
		if limit == 0 {
			wantCalls = 2
		}
		if calls != wantCalls {
			t.Fatal("unexpected build count", calls)
		}
		next, err := cache.RenderFeed(t.Context(), "version-2", func() ([]byte, error) { return []byte("changed"), nil })
		if err != nil || next.Tag == FeedTag([]byte("public")) {
			t.Fatal("stale version", next, err)
		}
		// Renderと同じキー文字列でも、異なる生成契約の結果を共有しない。
		body, err := cache.Render(t.Context(), "version-1", func() ([]byte, error) { return []byte("other"), nil })
		if err != nil || string(body) != "other" {
			t.Fatal("cache kind collision", string(body), err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := cache.RenderFeed(ctx, "version-1", render); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

func TestRenderedFeedSharesFlightAndEvictsMetadata(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := NewCompressionCache(1024, 1)
		entered, release := make(chan struct{}), make(chan struct{})
		var group sync.WaitGroup
		group.Go(func() {
			_, err := cache.RenderFeed(t.Context(), "same", func() ([]byte, error) {
				close(entered)
				<-release
				return []byte("first"), nil
			})
			if err != nil {
				t.Error(err)
			}
		})
		<-entered
		group.Go(func() {
			feed, err := cache.RenderFeed(t.Context(), "same", func() ([]byte, error) { t.Error("duplicate build"); return nil, nil })
			if err != nil || feed.Tag != FeedTag([]byte("first")) {
				t.Error(feed, err)
			}
		})
		synctest.Wait()
		close(release)
		group.Wait()
		cache.Configure(0, 1)
		if s := cache.Status(); s.Entries != 0 || s.Used != 0 {
			t.Fatal("metadata retained", s)
		}
		feed, err := cache.RenderFeed(t.Context(), "same", func() ([]byte, error) { return []byte("second"), nil })
		if err != nil || feed.Tag != FeedTag([]byte("second")) {
			t.Fatal(feed, err)
		}
	})
}
