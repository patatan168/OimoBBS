// 現行保存codecのサイズ境界、破損拒否、退役したgzip形式の拒否を検証する。
package store

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"testing"
)

func TestPackChunkRoundTrip(t *testing.T) {
	random := make([]byte, MaxPackRaw)
	_, _ = rand.New(rand.NewSource(1)).Read(random)
	for _, raw := range [][]byte{{0}, bytes.Repeat([]byte("投稿<>"), 1000), random} {
		for _, level := range []uint8{0, 1, 6, 9} {
			chunk, err := EncodePackChunk(raw, level)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodePackChunk(chunk)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatalf("level %d: %v", level, err)
			}
			got[0] ^= 1
			again, err := DecodePackChunk(chunk)
			if err != nil || !bytes.Equal(again, raw) {
				t.Fatal("decoded bytes alias storage")
			}
			if level == 0 {
				saved := chunk.Stored[0]
				raw[0] ^= 1
				if chunk.Stored[0] != saved {
					t.Fatal("encoded bytes alias input")
				}
				raw[0] ^= 1
			}
		}
	}
	for _, size := range []int{0, MaxPackRaw + 1} {
		if _, err := EncodePackChunk(make([]byte, size), 1); !errors.Is(err, ErrCorrupt) {
			t.Fatal(size, err)
		}
	}
	for _, level := range []uint8{2, 5, 7, 255} {
		if _, err := EncodePackChunk([]byte{1}, level); !errors.Is(err, ErrCorrupt) {
			t.Fatal(level, err)
		}
	}
}

func TestPackChunkRejects(t *testing.T) {
	raw := bytes.Repeat([]byte("data"), 100)
	tests := map[string]func(*PackChunk){
		"codec":            func(c *PackChunk) { c.Codec = 1 },
		"level":            func(c *PackChunk) { c.Level = 2 },
		"zero raw":         func(c *PackChunk) { c.RawLength = 0 },
		"large raw":        func(c *PackChunk) { c.RawLength = MaxPackRaw + 1 },
		"empty stored":     func(c *PackChunk) { c.Stored = nil },
		"large stored":     func(c *PackChunk) { c.Stored = make([]byte, MaxPackStored+1) },
		"stored crc":       func(c *PackChunk) { c.StoredCRC++ },
		"raw crc":          func(c *PackChunk) { c.RawCRC++ },
		"overflow":         func(c *PackChunk) { c.RawLength-- },
		"short output":     func(c *PackChunk) { c.RawLength++ },
		"second frame":     func(c *PackChunk) { c.Stored = append(c.Stored, c.Stored...); c.StoredCRC = checksum(c.Stored) },
		"trailing garbage": func(c *PackChunk) { c.Stored = append(c.Stored, 0); c.StoredCRC = checksum(c.Stored) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c, _ := EncodePackChunk(raw, 6)
			change(&c)
			got, err := DecodePackChunk(c)
			if !errors.Is(err, ErrCorrupt) || got != nil {
				t.Fatalf("accepted corrupt chunk: %v", err)
			}
		})
	}
	c, _ := EncodePackChunk(raw, 0)
	for _, change := range []func(*PackChunk){func(c *PackChunk) { c.Level = 1 }, func(c *PackChunk) { c.RawLength++ }, func(c *PackChunk) { c.RawCRC++ }} {
		bad := c
		change(&bad)
		if _, err := DecodePackChunk(bad); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
	}
	valid, _ := EncodePackChunk(raw, 6)
	for end := 0; end < len(valid.Stored); end++ {
		c := valid
		c.Stored = c.Stored[:end]
		c.StoredCRC = checksum(c.Stored)
		if _, err := DecodePackChunk(c); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("truncated at %d: %v", end, err)
		}
	}
	for _, field := range []string{"name", "comment", "extra", "empty extra"} {
		t.Run(field, func(t *testing.T) {
			var b bytes.Buffer
			z := gzip.NewWriter(&b)
			switch field {
			case "name":
				z.Name = "x"
			case "comment":
				z.Comment = "x"
			case "extra":
				z.Extra = []byte{1}
			case "empty extra":
				z.Extra = []byte{}
			}
			_, _ = z.Write(raw)
			_ = z.Close()
			c := PackChunk{Codec: 1, Level: 6, RawLength: uint32(len(raw)), RawCRC: checksum(raw), StoredCRC: checksum(b.Bytes()), Stored: b.Bytes()}
			if _, err := DecodePackChunk(c); !errors.Is(err, ErrCorrupt) {
				t.Fatal(err)
			}
		})
	}
}

// 現行fixtureの全本文ブロックと監査chunkをproduction codecで復号する。
func TestPackChunkDesignFixture(t *testing.T) {
	data, err := os.ReadFile("../../docs/design/fixtures/pack-zstd-layout.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Pack string `json:"pack_hex"`
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	p, err := hex.DecodeString(f.Pack)
	if err != nil {
		t.Fatal(err)
	}
	index := le.Uint64(p[120:])
	count := le.Uint32(p[84:])
	for i := uint32(0); i < count; i++ {
		e := p[index+uint64(i)*96:]
		off := le.Uint64(e[24:])
		size := le.Uint32(e[32:])
		c := PackChunk{e[40], e[41], le.Uint32(e[36:]), le.Uint32(e[48:]), le.Uint32(e[44:]), p[off : off+uint64(size)]}
		raw, err := DecodePackChunk(c)
		if err != nil || !bytes.HasPrefix(raw, []byte("OIMOBLK1")) {
			t.Fatal(i, err)
		}
	}
	off := le.Uint64(p[168:])
	audit := p[off:]
	chunks := le.Uint32(audit[24:])
	pos := uint64(32)
	for i := uint32(0); i < chunks; i++ {
		e := audit[pos:]
		size := le.Uint32(e[8:])
		c := PackChunk{e[12], e[13], le.Uint32(e[4:]), le.Uint32(e[16:]), le.Uint32(e[20:]), e[24 : 24+size]}
		if _, err := DecodePackChunk(c); err != nil {
			t.Fatal(err)
		}
		pos += 24 + uint64(size)
	}
}

// 任意の索引値・保存byteからpanicせず、受理時は宣言した内容だけを返す。
func FuzzDecodePackChunk(f *testing.F) {
	for _, level := range []uint8{0, 1, 6, 9} {
		c, _ := EncodePackChunk([]byte("post<>name<>date<>body<>title\n"), level)
		f.Add(c.Codec, c.Level, c.RawLength, c.RawCRC, c.StoredCRC, c.Stored)
	}
	f.Fuzz(func(t *testing.T, codec, level uint8, size, rawCRC, storedCRC uint32, stored []byte) {
		c := PackChunk{codec, level, size, rawCRC, storedCRC, stored}
		raw, err := DecodePackChunk(c)
		if err != nil {
			if raw != nil {
				t.Fatal("partial output")
			}
			return
		}
		if len(raw) != int(size) || len(raw) > MaxPackRaw || checksum(raw) != rawCRC {
			t.Fatal("invalid output")
		}
		encoded, err := EncodePackChunk(raw, level)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodePackChunk(encoded)
		if err != nil || !bytes.Equal(raw, decoded) {
			t.Fatal("round trip", err)
		}
	})
}
