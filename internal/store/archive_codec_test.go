// 現行Zstandard保存の原本一致、整合検査、切断・末尾拒否を検証する。
package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"oimobbs/internal/testutil"
	"os"
	"sync"
	"testing"
)

func TestArchiveChunkIntegrity(t *testing.T) {
	random := make([]byte, MaxPackRaw)
	rand.New(rand.NewSource(51)).Read(random)
	for _, raw := range [][]byte{{1}, bytes.Repeat([]byte("本文<>metadata<>"), 1000), random} {
		for _, level := range []uint8{1, 6, 9} {
			chunk, err := EncodePackChunk(raw, level)
			if err != nil || chunk.Codec != 2 {
				t.Fatal(chunk.Codec, err)
			}
			external, err := testutil.DecodeZstd(chunk.Stored)
			if err != nil || !bytes.Equal(external, raw) {
				t.Fatal("independent decoder", err)
			}
			got, err := DecodePackChunk(chunk)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatal("stored decode", err)
			}
			got[0] ^= 1
			again, err := DecodePackChunk(chunk)
			if err != nil || !bytes.Equal(again, raw) {
				t.Fatal("shared decode output")
			}
			saved := bytes.Clone(chunk.Stored)
			raw[0] ^= 1
			if !bytes.Equal(saved, chunk.Stored) {
				t.Fatal("shared input")
			}
			raw[0] ^= 1
		}
	}
	raw := bytes.Repeat([]byte("block text"), 30)
	original, err := EncodePackChunk(raw, 9)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*PackChunk){
		"codec": func(c *PackChunk) { c.Codec = 3 }, "level": func(c *PackChunk) { c.Level = 0 }, "rawCRC": func(c *PackChunk) { c.RawCRC++ }, "storedCRC": func(c *PackChunk) { c.StoredCRC++ }, "size": func(c *PackChunk) { c.RawLength++ }, "oversize": func(c *PackChunk) { c.RawLength = MaxPackRaw + 1 },
		"dictionary": func(c *PackChunk) { c.Stored[4] |= 1; c.StoredCRC = checksum(c.Stored) }, "checksum": func(c *PackChunk) { c.Stored[4] |= 4; c.StoredCRC = checksum(c.Stored) }, "reserved": func(c *PackChunk) { c.Stored[4] |= 8; c.StoredCRC = checksum(c.Stored) },
		"trailing": func(c *PackChunk) { c.Stored = append(c.Stored, 0); c.StoredCRC = checksum(c.Stored) }, "secondFrame": func(c *PackChunk) { c.Stored = append(c.Stored, c.Stored...); c.StoredCRC = checksum(c.Stored) },
	} {
		t.Run(name, func(t *testing.T) {
			chunk := original
			chunk.Stored = bytes.Clone(chunk.Stored)
			change(&chunk)
			if out, err := DecodePackChunk(chunk); err == nil || out != nil {
				t.Fatal("invalid chunk accepted")
			}
		})
	}
	for i := range len(original.Stored) {
		chunk := original
		chunk.Stored = bytes.Clone(original.Stored[:i])
		chunk.StoredCRC = checksum(chunk.Stored)
		if _, err := DecodePackChunk(chunk); err == nil {
			t.Fatal("truncation", i)
		}
	}
}

func TestArchivePackOriginalPreserved(t *testing.T) {
	old := packFixture(t)
	snapshot, err := DecodePack(old)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := EncodePack(snapshot, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []uint8{1, 6, 9} {
		packed, err := EncodePack(snapshot, level)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := DecodePack(packed)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := EncodePack(restored, 0)
		if err != nil || !bytes.Equal(normalized, expected) {
			t.Fatal("archive changed original", err)
		}
		if packCompressionCodec(packed) != 2 || packMinimumLevel(packed) != level {
			t.Fatal("archive policy")
		}
		dat := bytes.Join(snapshot.State.Lines, nil)
		for offset := range len(dat) {
			got, err := ReadPackDAT(packed, uint64(offset), uint64(len(dat)))
			if err != nil || !bytes.Equal(got, dat[offset:]) {
				t.Fatal("archive Range", offset, err)
			}
		}
	}
}

// TestArchiveSharedWorker は板をまたぐ同時生成でも専有結果と内容一致を維持する。
func TestArchiveSharedWorker(t *testing.T) {
	var workers sync.WaitGroup
	for i := range 40 {
		workers.Go(func() {
			raw := bytes.Repeat([]byte{byte(i), 42, 0, 255}, 2048)
			chunk, err := EncodePackChunk(raw, 9)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := DecodePackChunk(chunk)
			if err != nil || !bytes.Equal(got, raw) {
				t.Error("shared worker changed bytes", err)
			}
		})
	}
	workers.Wait()
}

// TestArchiveStoredFixture は既存Zstandard fixtureの原本・保存byte不変を独立復号で検査する。
func TestArchiveStoredFixture(t *testing.T) {
	file, err := os.ReadFile("../../docs/design/fixtures/pack-zstd-layout.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Hex string `json:"pack_hex"`
	}
	if err = json.Unmarshal(file, &fixture); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(fixture.Hex)
	if err != nil {
		t.Fatal(err)
	}
	current, err := DecodePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodePack(current, 9)
	if err != nil || !bytes.Equal(encoded, raw) || packCompressionCodec(raw) != 2 {
		t.Fatal("stored fixture byte changed", err)
	}

	_, _, blocks, err := parsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range blocks {
		decoded, e := testutil.DecodeZstd(block.chunk.Stored)
		if e != nil || checksum(decoded) != block.chunk.RawCRC {
			t.Fatal("independent fixed fixture", e)
		}
	}
}

// TestRetiredGzipPackRejected は整合する旧fixtureでも現行保存形式として受理しないことを検査する。
func TestRetiredGzipPackRejected(t *testing.T) {
	file, err := os.ReadFile("../../docs/design/fixtures/pack-v1-layout.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Hex string `json:"pack_hex"`
	}
	if err = json.Unmarshal(file, &f); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(f.Hex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodePack(raw); err == nil {
		t.Fatal("retired gzip pack accepted")
	}
}
