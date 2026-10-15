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
