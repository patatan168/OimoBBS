// pack復元と範囲読取りが意味検証・結果の専有・破損時の部分結果拒否を維持することを検査する。
package store

import (
	"bytes"
	"testing"
)

// repairPlainBlockChecksums はcodec=0のblock改変後に外枠を修復し、意味検証まで到達させる。
func repairPlainBlockChecksums(packed []byte, blockIndex int, block packBlock) {
	index := int(le.Uint64(packed[120:])) + blockIndex*96
	crc := checksum(block.chunk.Stored)
	le.PutUint32(packed[index+44:], crc)
	le.PutUint32(packed[index+48:], crc)
	le.PutUint32(packed[index+92:], checksum(packed[index:index+92]))
	repairPackChecksums(packed)
}

func TestPackRejectsInvalidDATOutsideRequestedSpan(t *testing.T) {
	packed, _ := largePackFixture(t)
	s, err := DecodePack(packed)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := EncodePack(s, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, blocks, err := parsePack(plain)
	if err != nil {
		t.Fatal(err)
	}
	blockIndex := len(blocks) - 1
	block := blocks[blockIndex]
	at := bytes.LastIndex(block.chunk.Stored, []byte("parallel zstd decode"))
	if at < 0 {
		t.Fatal("fixture needs a DAT body in the final block")
	}
	// JSONと索引は有効なまま、要求しない最後の行の本文へNULを入れる。
	plain[int(block.offset)+at] = 0
	repairPlainBlockChecksums(plain, blockIndex, block)
	if _, _, _, err := parsePack(plain); err != nil {
		t.Fatal("fixture must pass outer checks", err)
	}
	if got, err := DecodePack(plain); err == nil || got.State != nil {
		t.Fatal("invalid DAT returned in snapshot", err)
	}
	if got, err := ReadPackDAT(plain, block.start, block.start+1); err == nil || got != nil {
		t.Fatal("invalid unrequested line or partial DAT returned", err)
	}
}

func TestPackRejectsInvalidPostWithValidDATHash(t *testing.T) {
	s, err := DecodePack(packFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := EncodePack(s, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, blocks, err := parsePack(plain)
	if err != nil {
		t.Fatal(err)
	}
	block := blocks[0]
	key := []byte(`"source_ip":"`)
	at := bytes.Index(block.chunk.Stored, key)
	if at < 0 {
		t.Fatal("fixture requires source IP")
	}
	// DATとそのSHA-256は変えず、JSONとして有効な不正IPへ改変する。
	plain[int(block.offset)+at+len(key)] = 'x'
	repairPlainBlockChecksums(plain, 0, block)
	if _, _, _, err := parsePack(plain); err != nil {
		t.Fatal("fixture must pass outer checks", err)
	}
	if got, err := DecodePack(plain); err == nil || got.State != nil {
		t.Fatal("semantically invalid post returned", err)
	}
	if got, err := ReadPackDAT(plain, 0, 1); err == nil || got != nil {
		t.Fatal("invalid post bypassed by DAT range", err)
	}
}

func TestPackResultsOwnTheirBytes(t *testing.T) {
	packed, dat := largePackFixture(t)
	s, err := DecodePack(packed)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(s.State.Lines[1])
	clear(s.State.Lines[0])
	if !bytes.Equal(s.State.Lines[1], before) {
		t.Fatal("snapshot lines alias one another")
	}
	got, err := ReadPackDAT(packed, 0, uint64(len(dat)))
	if err != nil || !bytes.Equal(got, dat) {
		t.Fatal("snapshot write changed pack", err)
	}
	clear(got)
	again, err := ReadPackDAT(packed, 0, uint64(len(dat)))
	if err != nil || !bytes.Equal(again, dat) {
		t.Fatal("range result aliases pack or another decode", err)
	}
}
