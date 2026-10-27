// 実際の保存DTOで一件内の並列符号化を標準JSONと照合し、前版との測定入力を固定する。
package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"oimobbs/internal/strictjson"
	"runtime"
	"strings"
	"testing"
)

func singleJSONPosts(count int) Append {
	v := Append{Posts: make([]Post, count)}
	for i := range v.Posts {
		v.Posts[i] = Post{Number: uint32(i + 1), Kind: "post", Visibility: "public", Created: Time(i + 1),
			Name: "投稿者", Body: strings.Repeat("本文日本語<&>\\\"\n😀", 30),
			Private: &Private{SourceIP: "192.0.2.1", CapID: &ID{1}, RateKeys: []RateKey{{ID{2}, uint32(i), Hash{3}, 1}}}}
	}
	return v
}

func TestGeneratedDomainParallelJSON(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	v := singleJSONPosts(256)
	for _, bad := range []int{-1, 0, 100, 255} {
		if bad >= 0 {
			v.Posts[bad].Private.CapID = &ID{}
		}
		want, we := json.Marshal(v)
		got, ge := MarshalAppend(v)
		if (we == nil) != (ge == nil) || we == nil && !bytes.Equal(want, got) || ge != nil && got != nil {
			t.Fatal("generated parallel encoding differs", bad, we, ge)
		}
		if bad >= 0 {
			v.Posts[bad].Private.CapID = &ID{1}
		}
	}
}

func BenchmarkSingleJSONPosts(b *testing.B) {
	for _, count := range []int{1, 128, 512} {
		v := singleJSONPosts(count)
		raw, err := json.Marshal(v)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("posts%d/encode", count), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for range b.N {
				if _, err := MarshalAppend(v); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("posts%d/decode", count), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for range b.N {
				var got Append
				if err := strictjson.DecodeLimit(raw, &got, 8<<20); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSingleJSONPostsConcurrent(b *testing.B) {
	for _, count := range []int{1, 128} {
		v := singleJSONPosts(count)
		raw, err := json.Marshal(v)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("posts%d/encode", count), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := MarshalAppend(v); err != nil {
						b.Error(err)
					}
				}
			})
		})
		b.Run(fmt.Sprintf("posts%d/decode", count), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					var got Append
					if err := strictjson.DecodeLimit(raw, &got, 8<<20); err != nil {
						b.Error(err)
					}
				}
			})
		})
	}
}
