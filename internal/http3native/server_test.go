// 既存HTTP/3 clientから独自QUIC/HTTP/3を経由し、HTTPの実入出力を検証する。
package http3native

import (
	"bytes"
	"context"

	"fmt"
	"io"

	"strings"

	"testing"
)

func TestRequestFieldsValidation(t *testing.T) {
	valid := []Field{{":method", "POST"}, {":scheme", "https"}, {":authority", "localhost"}, {":path", "/echo"}, {"content-length", "3"}}
	if _, err := requestFields(valid, t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []Field{{":method", "GET"}, {"Content-Type", "x"}, {"connection", "close"}, {"content-length", "4"}, {"x-test", "bad\r\nvalue"}, {"te", "gzip"}} {
		if _, err := requestFields(append(append([]Field{}, valid...), extra), t.Context()); err == nil {
			t.Errorf("accepted %+v", extra)
		}
	}
}
func TestQPACKStaticAndDynamic(t *testing.T) {
	fields := []Field{{":status", "304"}, {"etag", strings.Repeat("unchanged", 16)}, {"date", "Tue, 03 Nov 2026 00:00:00 GMT"}}
	encoder := newQPACK(nil, nil)
	if err := encoder.configure(4096, 16); err != nil {
		t.Fatal(err)
	}
	first, err := encoder.encode(0, fields)
	if err != nil {
		t.Fatal(err)
	}
	// encoderの参照に先行して届く命令を独立したdecoderへ入力する。
	decoder := newQPACK(nil, nil)
	instructions := appendPrefix(nil, 0x20, 5, 4096)
	for _, e := range encoder.tx.entries {
		instructions = appendString(instructions, 0x40, 5, 0x20, e.Name)
		instructions = appendString(instructions, 0, 7, 0x80, e.Value)
	}
	if err := decoder.readEncoder(bytes.NewReader(instructions)); err != io.EOF {
		t.Fatal(err)
	}
	got, err := decoder.decode(t.Context(), 0, first)
	if err != nil || len(got) != len(fields) {
		t.Fatalf("decode: %+v %v", got, err)
	}
	for i := range fields {
		if got[i] != fields[i] {
			t.Fatalf("field %+v", got)
		}
	}
	if err := encoder.readDecoder(bytes.NewReader(appendPrefix(nil, 0x80, 7, 0))); err != io.EOF {
		t.Fatal(err)
	}
	repeated, err := encoder.encode(4, fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(repeated) != 5 {
		t.Fatalf("repeated header bytes=%d", len(repeated))
	}
	t.Logf("repeated 304 header block=%d bytes", len(repeated))
	for _, bad := range [][]byte{{0, 0, 0xff, 0x25}, {0, 0, 0x80}, {0xff}, {0, 0, 0x23, 'b', 'a', 'd', 0x81, 0xff}} {
		if _, err := newQPACK(nil, nil).decode(t.Context(), 4, bad); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
	if err := newQPACK(nil, nil).readEncoder(strings.NewReader("\x41a\x01b")); err == nil || err == io.EOF {
		t.Fatal("insert without capacity")
	}
}
func FuzzQPACKDecode(f *testing.F) {
	f.Add([]byte{0, 0, 0xd9})
	f.Add([]byte{0, 0, 0xff, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, _ = newQPACK(nil, nil).decode(ctx, 0, data)
	})
}

func TestQPACKInsertCountWrapAndEviction(t *testing.T) {
	tx, rx := newQPACK(nil, nil), newQPACK(nil, nil)
	if err := tx.configure(4096, 16); err != nil {
		t.Fatal(err)
	}
	if err := rx.readEncoder(bytes.NewReader(appendPrefix(nil, 0x20, 5, 4096))); err != io.EOF {
		t.Fatal(err)
	}
	count := uint64(0)
	for i := range 600 {
		fields := []Field{{":status", "304"}, {"etag", fmt.Sprintf("changed-%04d%s", i, strings.Repeat("cache", 24))}, {"date", "Tue, 03 Nov 2026 00:00:00 GMT"}}
		id := uint64(i * 4)
		block, err := tx.encode(id, fields)
		if err != nil {
			t.Fatal(err)
		}
		var instructions []byte
		for _, entry := range tx.tx.entries {
			if entry.absolute >= count {
				instructions = appendString(instructions, 0x40, 5, 0x20, entry.Name)
				instructions = appendString(instructions, 0, 7, 0x80, entry.Value)
			}
		}
		count = tx.tx.count
		if err := rx.readEncoder(bytes.NewReader(instructions)); err != io.EOF {
			t.Fatal(err)
		}
		got, err := rx.decode(t.Context(), id, block)
		if err != nil || fmt.Sprint(got) != fmt.Sprint(fields) {
			t.Fatalf("round %d: %v %v", i, got, err)
		}
		if err = tx.readDecoder(bytes.NewReader(appendPrefix(nil, 0x80, 7, id))); err != io.EOF {
			t.Fatal(err)
		}
	}
	if tx.tx.count < 600 || tx.tx.size > 4096 || rx.rx.size > 4096 {
		t.Fatal("table budget/wrap", tx.tx.count)
	}
}
func TestQPACKSensitiveFieldsNotIndexed(t *testing.T) {
	q := newQPACK(nil, nil)
	_ = q.configure(4096, 16)
	block, err := q.encode(0, []Field{{"cookie", "secret-token"}, {"set-cookie", "private=value"}, {"authorization", "Bearer token"}})
	if err != nil {
		t.Fatal(err)
	}
	if q.tx.count != 0 || block[2]&0x20 == 0 {
		t.Fatal("sensitive field indexed")
	}
}
