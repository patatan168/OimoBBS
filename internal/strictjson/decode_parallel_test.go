// 一件内の並列復号を逐次復号と照合し、不正末尾・独自復号・深さ・要素順を検証する。
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"oimobbs/internal/parallel"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type parallelRow struct {
	Number int             `json:"number"`
	Text   string          `json:"text"`
	Nested []uint64        `json:"nested"`
	Custom parallelOrdinal `json:"custom"`
}

type parallelDocument struct {
	Rows []parallelRow `json:"rows"`
	Tail bool          `json:"tail"`
}

type parallelOrdinal int

var parallelOrdinals []int

func (v *parallelOrdinal) UnmarshalJSON(raw []byte) error {
	if err := json.Unmarshal(raw, (*int)(v)); err != nil {
		return err
	}
	parallelOrdinals = append(parallelOrdinals, int(*v))
	return nil
}

func parallelFixture(t testing.TB, count int) []byte {
	t.Helper()
	doc := parallelDocument{Rows: make([]parallelRow, count), Tail: true}
	for i := range doc.Rows {
		doc.Rows[i] = parallelRow{i, strings.Repeat("日本語<&>\n😀", 80), []uint64{0, uint64(i), ^uint64(0)}, parallelOrdinal(i)}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSingleJSONParallelDecode(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	raw := parallelFixture(t, 256)
	var want, got parallelDocument
	parallelOrdinals = nil
	if _, err := decodeCheckedMode(raw, reflect.ValueOf(&want).Elem(), MaxBytes, "", false, true); err != nil {
		t.Fatal(err)
	}
	parallelOrdinals = nil
	if err := Decode(raw, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("parallel result differs", err)
	}
	for i, n := range parallelOrdinals {
		if n != i {
			t.Fatal("custom callback order changed", i, n)
		}
	}
	if len(parallelOrdinals) != 256 {
		t.Fatal("custom callbacks lost", len(parallelOrdinals))
	}
	// 走査器へ直接与えて、試験入力が複数の分担範囲になることも確認する。
	d := checkedDecoder{checkedScanner: checkedScanner{keyScanner: keyScanner{body: raw, pos: len(`{"rows":[`)}, strict: true}, depth: 2, workers: 4}
	if n, spans, err := d.arrayLayout(); err != nil || n != 256 || len(spans) < 2 {
		t.Fatal("fixture did not split", n, len(spans), err)
	}
}

func TestSingleJSONParallelRejectsBeforeCallbacks(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	raw := parallelFixture(t, 256)
	for _, bad := range [][]byte{
		append(bytes.Clone(raw), []byte(` trailing`)...),
		bytes.Replace(raw, []byte(`"tail":true`), []byte(`"tail":null`), 1),
		bytes.Replace(raw, []byte(`"number":200`), []byte(`"number":200,"number":1`), 1),
		bytes.Replace(raw, []byte(`"number":200`), []byte(`"number":-0`), 1),
		bytes.Replace(raw, []byte(`"number":200`), []byte(`"number":18446744073709551616`), 1),
		bytes.Replace(raw, []byte(`"number":200`), []byte(`"unknown":200`), 1),
		bytes.Replace(raw, []byte(`"number":200`), []byte(`"number":200,"bad":"\ud800"`), 1),
		bytes.Replace(raw, []byte(`"nested":[0,200,18446744073709551615]`), []byte(`"nested":[0,]`), 1),
	} {
		var got parallelDocument
		parallelOrdinals = nil
		if err := Decode(bad, &got); err == nil || len(parallelOrdinals) != 0 || !reflect.DeepEqual(got, parallelDocument{}) {
			t.Fatal("invalid input published data/called custom decoder", err, len(parallelOrdinals))
		}
	}
}

func TestSingleJSONParallelConcurrentAndFallback(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	type doc struct {
		Rows []string `json:"rows"`
	}
	want := doc{Rows: make([]string, 256)}
	for i := range want.Rows {
		want.Rows[i] = fmt.Sprint(i) + strings.Repeat("検査<&>😀", 100)
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	check := func() {
		var got doc
		if err := Decode(raw, &got); err != nil || !reflect.DeepEqual(got, want) {
			t.Error("concurrent/fallback decode changed output", err)
		}
	}
	if !parallel.TryCPU(4, func(i int) {
		if i == 0 {
			check() // 追加worker枠が全て使用中でも同じJSONを逐次復号できる。
		}
	}) {
		t.Fatal("failed to reserve worker budget")
	}
	var pending sync.WaitGroup
	for range 8 {
		pending.Go(check)
	}
	pending.Wait()
}

func TestSingleJSONParallelCallbackGroups(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	type doc struct {
		Before parallelOrdinal `json:"before"`
		Rows   []parallelRow   `json:"rows"`
		Middle parallelOrdinal `json:"middle"`
		More   []parallelRow   `json:"more"`
		After  parallelOrdinal `json:"after"`
	}
	var rows parallelDocument
	if err := json.Unmarshal(parallelFixture(t, 128), &rows); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc{-10, rows.Rows, -20, rows.Rows, -30})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{raw, bytes.Replace(raw, []byte(`"custom":100`), []byte(`"custom":"bad"`), 1)} {
		var want, got doc
		parallelOrdinals = nil
		_, we := decodeCheckedMode(body, reflect.ValueOf(&want).Elem(), MaxBytes, "", false, true)
		order := append([]int(nil), parallelOrdinals...)
		parallelOrdinals = nil
		ge := Decode(body, &got)
		if (we == nil) != (ge == nil) || !reflect.DeepEqual(want, got) || !reflect.DeepEqual(order, parallelOrdinals) {
			t.Fatal("deferred groups changed output/order/errors", we, ge)
		}
	}
}

func FuzzSingleJSONParallel(f *testing.F) {
	f.Add("日本語<&>\n", uint16(200), uint8(0))
	f.Add("😀\\\"", uint16(128), uint8(1))
	f.Fuzz(func(t *testing.T, text string, count uint16, change uint8) {
		// 大きな配列を維持しつつ、fuzz一回の保持量とworker数を有界にする。
		count = 128 + count%129
		if len(text) > 1024 {
			text = text[:1024]
		}
		type row struct {
			Text string `json:"text"`
			N    int    `json:"n"`
		}
		type doc struct {
			Rows []row `json:"rows"`
		}
		v := doc{Rows: make([]row, count)}
		for i := range v.Rows {
			v.Rows[i] = row{text + strings.Repeat("x", 1024), i}
		}
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if change%2 != 0 {
			raw[len(raw)/2] = change
		}
		var want, got doc
		_, we := decodeCheckedMode(raw, reflect.ValueOf(&want).Elem(), MaxBytes, "", false, true)
		ge := Decode(raw, &got)
		if (we == nil) != (ge == nil) || we == nil && !reflect.DeepEqual(want, got) || ge != nil && !reflect.DeepEqual(got, doc{}) {
			t.Fatal("parallel acceptance/output differs", we, ge)
		}
	})
}

func BenchmarkSingleJSONDecode(b *testing.B) {
	for _, count := range []int{1, 128, 512} {
		// callbackの副作用を計時へ混ぜず、通常の文字列・整数・入れ子を使う。
		type row struct {
			N    int      `json:"n"`
			Text string   `json:"text"`
			Nums []uint64 `json:"nums"`
		}
		type doc struct {
			Rows []row `json:"rows"`
		}
		v := doc{Rows: make([]row, count)}
		for i := range v.Rows {
			v.Rows[i] = row{i, strings.Repeat("投稿日本語<&>\\\"\n", 100), []uint64{0, uint64(i), ^uint64(0)}}
		}
		raw, err := json.Marshal(v)
		if err != nil {
			b.Fatal(err)
		}
		for _, serial := range []bool{true, false} {
			b.Run(fmt.Sprintf("items%d/serial%t", count, serial), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				for range b.N {
					var dst doc
					if _, err := decodeCheckedMode(raw, reflect.ValueOf(&dst).Elem(), 8<<20, "", false, serial); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
