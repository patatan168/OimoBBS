// 実HTMLの96MiB作業集合を、実行時と同じメモリ予算で巡回する。
package bootstrap

import (
	"bytes"
	"fmt"
	"testing"

	"oimobbs/internal/compat"
	"oimobbs/internal/platform"
	"oimobbs/internal/testutil"
)

// BenchmarkReadingAdaptiveMemory は本文の再生成数を比較する。TLS・NIC・投稿は含まない。
// CPU数は両条件とも4に固定し、メモリ増量による保持量の効果を分ける。
func BenchmarkReadingAdaptiveMemory(b *testing.B) {
	dat := testutil.DATFixture("entropy")
	numbers := make([]int, 200)
	for i := range numbers {
		numbers[i] = i + 1
	}
	render := func() ([]byte, error) {
		rows, err := threadRows(dat, 1000, numbers)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		err = threadTemplate.Execute(&out, threadPage{Title: "title", Key: "123", Board: "probe", Count: 1000, Rows: rows, CanReply: true})
		return out.Bytes(), err
	}
	expected, err := render()
	if err != nil {
		b.Fatal(err)
	}
	keys := make([]string, (96<<20)/cap(expected)+1)
	for i := range keys {
		keys[i] = fmt.Sprintf("independent-thread-version-%d", i)
	}
	for _, containerMiB := range []uint64{512, 2048} {
		b.Run(fmt.Sprintf("container=%dMiB", containerMiB), func(b *testing.B) {
			// 明示GOMEMLIMITなしのLinux起動と同じ75%のsoft limit。
			budget := containerMiB * 3 / 4 << 20
			limit, workers := representationResources(platform.MemoryState{Limit: budget, Headroom: budget}, 4)
			cache := compat.NewCompressionCache(limit, workers)
			for _, key := range keys {
				got, err := cache.RenderFeed(b.Context(), key, render)
				if err != nil || !bytes.Equal(got.Body, expected) {
					b.Fatal("different HTML", err)
				}
			}
			before := cache.Status()
			b.ReportAllocs()
			b.ResetTimer()
			i := 0
			for b.Loop() {
				if _, err := cache.RenderFeed(b.Context(), keys[i%len(keys)], render); err != nil {
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
