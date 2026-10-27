// 公開DATからの表示変換はHTMLを信頼せず、番号と改行を保持する。
package bootstrap

import (
	"bytes"
	"net/http/httptest"
	"oimobbs/internal/textcodec"
	"testing"
)

func TestThreadRowsSelectedOrderAndInvalidBytes(t *testing.T) {
	one, e := textcodec.Encode("名<>sage<>日時<>本文<>題\n", true)
	if e != nil {
		t.Fatal(e)
	}
	raw := bytes.Repeat(one, 1000)
	rows, e := threadRows(raw, 1000, []int{1000, 1, 500, 1})
	if e != nil || len(rows) != 4 {
		t.Fatal(rows, e)
	}
	for i, number := range []int{1000, 1, 500, 1} {
		if rows[i].Number != number || rows[i].Body != "本文" {
			t.Fatal("selection order changed", rows)
		}
	}
	for _, number := range []int{0, 1001} {
		if _, e := threadRows(raw, 1000, []int{number}); e == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	if _, e := threadRows([]byte{0x81, '\n'}, 1, []int{1}); e == nil {
		t.Fatal("invalid selected Shift_JIS accepted")
	}
}

func TestThreadRowsEscapeBoundary(t *testing.T) {
	raw, e := textcodec.Encode("名&lt;img&gt;<>sage<>日時 ID:abc<>本文<br>&lt;script&gt;&amp;lt;br&amp;gt;<>題\n", true)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := threadRows(raw, 1, []int{1})
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 1 || rows[0].Number != 1 || rows[0].Body != "本文\n<script>&lt;br&gt;" || rows[0].Name != "名<img>" {
		t.Fatal(rows)
	}
	if _, e = threadRows(raw, 2, []int{1}); e == nil {
		t.Fatal("count mismatch accepted")
	}
}

func TestThreadRequestSelectionBoundary(t *testing.T) {
	for _, path := range []string{"/test/read.cgi/other/123/1", "/test/read.cgi/news/0123/1", "/test/read.cgi/news/0/1", "/test/read.cgi/news/123/1/2", "/test/read.cgi/news/123/1?page=1&page=2", "/test/read.cgi/news/123/1?page=0", "/test/read.cgi/news/123/1?page=%zz"} {
		r := httptest.NewRequest("GET", path, nil)
		if _, _, _, e := threadRequest(r, "news"); e == nil {
			t.Fatal("invalid path accepted", path)
		}
	}
	r := httptest.NewRequest("GET", "/test/read.cgi/news/123/l50n?page=2", nil)
	key, selection, page, e := threadRequest(r, "news")
	if e != nil || key != 123 || selection != "l50n" || page != 2 {
		t.Fatal(key, selection, page, e)
	}
}

// TestThreadRowsSlipBoundary は固定DATタグを表示へ漏らさず、利用者のタグ文字は保持する。
func TestThreadRowsSlipBoundary(t *testing.T) {
	raw, e := textcodec.Encode("名&lt;b&gt; </b>(ﾜｯﾁｮｲ abcd-AbCd [192.0.2.1])<b><><>日時 ID:abcdefg0<>本文<>題\n", true)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := threadRows(raw, 1, []int{1})
	if e != nil || len(rows) != 1 || rows[0].Name != "名<b> (ﾜｯﾁｮｲ abcd-AbCd [192.0.2.1])" {
		t.Fatal(rows, e)
	}
}
