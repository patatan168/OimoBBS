// 同じ公開DATのHTML生成と共有取得を比較し、本文の一致を計測前に確認する。
package bootstrap

import (
	"bytes"
	"fmt"
	"testing"

	"oimobbs/internal/compat"
	"oimobbs/internal/testutil"
)

func BenchmarkThreadHTMLRepresentation(b *testing.B) {
	raw := testutil.DATFixture("entropy")
	numbers := make([]int, 50)
	for i := range numbers {
		numbers[i] = i + 1
	}
	render := func() ([]byte, error) {
		rows, err := threadRows(raw, 1000, numbers)
		if err != nil {
			return nil, err
		}
		var body bytes.Buffer
		err = threadTemplate.Execute(&body, threadPage{Title: "title", Key: "123", Board: "probe", Count: 1000, Rows: rows, CanReply: true})
		return body.Bytes(), err
	}
	expected, err := render()
	if err != nil {
		b.Fatal(err)
	}
	for _, shared := range []bool{false, true} {
		b.Run(fmt.Sprint("shared=", shared), func(b *testing.B) {
			cache := compat.NewCompressionCache(1<<20, 2)
			get := render
			if shared {
				get = func() ([]byte, error) { return cache.Render(b.Context(), "same-public-version", render) }
			}
			got, err := get()
			if err != nil || !bytes.Equal(got, expected) {
				b.Fatal("different HTML", err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(expected)))
			b.ResetTimer()
			for b.Loop() {
				if _, err := get(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkThreadHTMLWorkingSet は32MiB分の異なる公開版を巡回し、実HTMLの再生成費用を測る。
// 各キーは独立したスレッド版を模し、投稿による版更新やネットワークは含めない。
func BenchmarkThreadHTMLWorkingSet(b *testing.B) {
	raw := testutil.DATFixture("entropy")
	numbers := make([]int, 50)
	for i := range numbers {
		numbers[i] = i + 1
	}
	render := func() ([]byte, error) {
		rows, err := threadRows(raw, 1000, numbers)
		if err != nil {
			return nil, err
		}
		var body bytes.Buffer
		err = threadTemplate.Execute(&body, threadPage{Title: "title", Key: "123", Board: "probe", Count: 1000, Rows: rows, CanReply: true})
		return body.Bytes(), err
	}
	expected, err := render()
	if err != nil {
		b.Fatal(err)
	}
	keys := make([]string, (32<<20)/cap(expected)+1)
	if len(keys) > 1024 {
		b.Fatal("fixture exceeds cache entry bound", len(keys))
	}
	for i := range keys {
		keys[i] = fmt.Sprintf("thread-%d-public-version-1", i)
	}
	for _, limit := range []uint64{16 << 20, 128 << 20} {
		b.Run(fmt.Sprintf("cache=%dMiB", limit>>20), func(b *testing.B) {
			cache := compat.NewCompressionCache(limit, 4)
			for _, key := range keys {
				got, err := cache.Render(b.Context(), key, render)
				if err != nil || !bytes.Equal(got, expected) {
					b.Fatal("different HTML", err)
				}
			}
			before := cache.Status()
			b.ReportAllocs()
			b.ResetTimer()
			i := 0
			for b.Loop() {
				if _, err := cache.Render(b.Context(), keys[i%len(keys)], render); err != nil {
					b.Fatal(err)
				}
				i++
			}
			b.StopTimer()
			after := cache.Status()
			b.ReportMetric(float64(after.Builds-before.Builds)/float64(b.N), "builds/op")
			b.ReportMetric(float64(after.Used)/(1<<20), "retained-MiB")
		})
	}
}
