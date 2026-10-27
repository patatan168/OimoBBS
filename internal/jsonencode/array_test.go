// 並列符号化のbyte順、エラー、上界計算、再帰抑止を逐次出力と照合する。
package jsonencode

import (
	"bytes"
	"errors"
	"fmt"
	"oimobbs/internal/parallel"
	"runtime"
	"strings"
	"testing"
)

func TestParallelArrayOutput(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for _, fail := range []int{-1, 0, 130, 255} {
		failure := errors.New("element failed")
		appendRange := func(w *Writer, start, end int) {
			if !w.serial {
				t.Error("nested parallelism enabled")
			}
			for i := start; i < end; i++ {
				if i > start {
					w.Literal(",")
				}
				w.String(fmt.Sprint(i) + strings.Repeat("日本語<&>\n😀", 100))
				if i == fail {
					w.Err = failure
				}
			}
		}
		want := Writer{Bytes: []byte("prefix"), serial: true}
		appendRange(&want, 0, 256)
		got := Writer{Bytes: []byte("prefix")}
		if !TryArray(&got, 256, appendRange) || !bytes.Equal(got.Bytes, want.Bytes) || got.Err != want.Err {
			t.Fatal("parallel output/error differs", fail, got.Err, want.Err)
		}
	}
	for _, w := range []Writer{{BoundOnly: true, Limit: 1024}, {serial: true}, {}} {
		count := 256
		if !w.BoundOnly && !w.serial {
			count = 127
		}
		if TryArray(&w, count, func(*Writer, int, int) { t.Error("unexpected work") }) {
			t.Fatal("small/serial/bound path accepted")
		}
	}
	if !parallel.TryCPU(4, func(i int) {
		if i != 0 {
			return
		}
		w := Writer{Bytes: []byte("prefix")}
		if TryArray(&w, 256, func(part *Writer, start, end int) {
			part.String(strings.Repeat("x", 8192))
		}) || string(w.Bytes) != "prefix" || w.Err != nil {
			t.Error("budget exhaustion changed caller output")
		}
	}) {
		t.Fatal("failed to reserve worker budget")
	}
}

func BenchmarkSingleJSONEncode(b *testing.B) {
	for _, count := range []int{1, 128, 512} {
		items := make([]string, count)
		for i := range items {
			items[i] = fmt.Sprint(i) + strings.Repeat("投稿日本語<&>\\\"\n", 100)
		}
		appendRange := func(w *Writer, start, end int) {
			for i := start; i < end; i++ {
				if i > start {
					w.Literal(",")
				}
				w.String(items[i])
			}
		}
		for _, serial := range []bool{true, false} {
			b.Run(fmt.Sprintf("items%d/serial%t", count, serial), func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					w := Writer{Bytes: make([]byte, 0, 2048), serial: serial}
					w.Literal(`{"items":[`)
					if !TryArray(&w, count, appendRange) {
						appendRange(&w, 0, count)
					}
					w.Literal("]}")
					if w.Err != nil {
						b.Fatal(w.Err)
					}
				}
			})
		}
	}
}

func FuzzParallelArray(f *testing.F) {
	f.Add("日本語<&>\\\"\n😀", uint8(128))
	f.Add(string([]byte{255, 0, 1}), uint8(255))
	f.Fuzz(func(t *testing.T, text string, n uint8) {
		if len(text) > 1024 {
			text = text[:1024]
		}
		count := 128 + int(n)%129
		text += strings.Repeat("x", 1024)
		appendRange := func(w *Writer, start, end int) {
			for i := start; i < end; i++ {
				if i > start {
					w.Literal(",")
				}
				w.String(text)
			}
		}
		want := Writer{serial: true}
		appendRange(&want, 0, count)
		got := Writer{}
		if !TryArray(&got, count, appendRange) {
			appendRange(&got, 0, count)
		}
		if !bytes.Equal(want.Bytes, got.Bytes) || want.Err != got.Err {
			t.Fatal("parallel string array changed output")
		}
	})
}
