// 共有再実行WALの大きいrecord、長さ境界、破損と未完了末尾の区別を検証する。
package store

import (
	"bytes"
	"oimobbs/internal/domain"
	"reflect"
	"testing"
)

func TestThreadGroupLargeRecordRoundtrip(t *testing.T) {
	record := threadGroupRecord{Owner: domain.NewID(), Writes: []threadGroupWrite{{Key: 1, Generation: 2, Offset: 64, Block: bytes.Repeat([]byte{0, 1, 2, 255}, 512<<10)}}}
	raw, err := encodeThreadGroup(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != len(record.Writes[0].Block)+76 {
		t.Fatal("本文以外の長さ", len(raw))
	}
	got, err := decodeThreadGroups(raw)
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], record) {
		t.Fatal("1MiB超の保存を復旧できない", err)
	}
	for _, end := range []int{0, 1, 15, 16, 20, len(raw) - 1} {
		got, err := decodeThreadGroups(raw[:end])
		if err != nil || len(got) != 0 {
			t.Fatalf("未完了末尾 %d: %v", end, err)
		}
	}
	damaged := bytes.Clone(raw)
	damaged[len(damaged)-20] ^= 1
	if _, err := decodeThreadGroups(damaged); err == nil {
		t.Fatal("完全な破損を受理した")
	}
}

func TestThreadGroupBinaryLengthBoundaries(t *testing.T) {
	record := threadGroupRecord{Owner: domain.NewID(), Writes: []threadGroupWrite{{Key: 1, Generation: 1, Offset: 64, Block: []byte{1}}}}
	raw, err := encodeThreadGroup(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func([]byte){
		func(b []byte) { le.PutUint32(b[32:], 0) },
		func(b []byte) { le.PutUint32(b[32:], MaxCommitFrames+1) },
		func(b []byte) { le.PutUint32(b[60:], 0) },
		func(b []byte) { le.PutUint32(b[60:], ^uint32(0)) },
		func(b []byte) { le.PutUint32(b[32:], 2) },
	} {
		body := bytes.Clone(raw)
		change(body)
		le.PutUint32(body[len(body)-12:], checksum(body[16:len(body)-12]))
		if _, err := decodeThreadGroups(body); err == nil {
			t.Fatal("長さ不整合を受理した")
		}
	}
	if _, err := decodeThreadGroups(make([]byte, maxThreadGroupBytes+1)); err == nil {
		t.Fatal("file上限を超えた")
	}
	record.Writes[0].Block = make([]byte, maxThreadGroupBytes)
	if _, err := encodeThreadGroup(record); err == nil {
		t.Fatal("符号化上限を超えた")
	}
}
