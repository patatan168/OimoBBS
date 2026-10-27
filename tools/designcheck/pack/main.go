// pack設計fixtureを標準Goで独立に読み、配置・圧縮・参照を照合する確認用。
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
)

var le = binary.LittleEndian
var table = crc32.MakeTable(crc32.Castagnoli)

func check(b bool, s string) {
	if !b {
		panic(s)
	}
}
func obj(v any) map[string]any { return v.(map[string]any) }
func num(v any) uint64 {
	n, e := strconv.ParseUint(v.(string), 10, 64)
	if e != nil {
		panic(e)
	}
	return n
}
func dec(v any) []byte {
	b, e := hex.DecodeString(v.(string))
	if e != nil {
		panic(e)
	}
	return b
}
func crc(b []byte) uint32  { return crc32.Checksum(b, table) }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func jsonObj(b []byte) map[string]any {
	var v map[string]any
	if e := json.Unmarshal(b, &v); e != nil {
		panic(e)
	}
	return v
}
func unpack(stored []byte, codec byte, size int) ([]byte, error) {
	if size < 1 || size > 524288 || len(stored) > 540672 {
		return nil, errors.New("size")
	}
	if codec == 0 {
		if len(stored) != size {
			return nil, errors.New("raw size")
		}
		return stored, nil
	}
	if codec != 1 {
		return nil, errors.New("codec")
	}
	br := bytes.NewReader(stored)
	z, e := gzip.NewReader(br)
	if e != nil {
		return nil, e
	}
	defer z.Close()
	z.Multistream(false)
	if z.Name != "" || z.Comment != "" || len(z.Extra) != 0 || z.OS != 255 || !z.ModTime.IsZero() {
		return nil, errors.New("gzip header")
	}
	raw, e := io.ReadAll(io.LimitReader(z, int64(size)+1))
	if e != nil {
		return nil, e
	}
	if len(raw) != size || br.Len() != 0 {
		return nil, errors.New("gzip size or trailing member")
	}
	return raw, nil
}
func current(s string, pack, delta []byte) map[string]any {
	var outer struct {
		Manifest json.RawMessage `json:"manifest"`
		Checksum string          `json:"manifest_sha256"`
	}
	if e := json.Unmarshal([]byte(s), &outer); e != nil {
		panic(e)
	}
	check(hash(outer.Manifest) == outer.Checksum, "manifest exact bytes")
	m := jsonObj(outer.Manifest)
	b := obj(m["base"])
	d := obj(m["delta"])
	check(hash(pack) == b["sha256"] && uint64(len(pack)) == num(b["length"]), "base hash/length")
	check(num(b["seq"]) == le.Uint64(pack[48:56]) && num(b["dat_generation"]) == le.Uint64(pack[56:64]), "base versions")
	check(num(d["base_seq"]) == le.Uint64(delta[40:48]), "delta base")
	check(num(m["storage_generation"]) == le.Uint64(delta[48:56]) && num(m["storage_generation"]) == le.Uint64(pack[40:48]), "storage generation")
	check(bytes.Equal(dec(m["board_id"]), pack[16:32]) && bytes.Equal(pack[16:32], delta[16:32]), "board")
	check(num(m["thread_key"]) == le.Uint64(pack[32:40]) && le.Uint64(pack[32:40]) == le.Uint64(delta[32:40]), "thread")
	n := num(d["required_end"])
	check(n <= uint64(len(delta)) && hash(delta[:n]) == d["required_sha256"], "required prefix")
	return m
}
func main() {
	data, e := os.ReadFile("docs/design/fixtures/pack-v1-layout.json")
	if e != nil {
		panic(e)
	}
	f := jsonObj(data)
	p := dec(f["pack_hex"])
	check(len(p) == int(f["pack_length"].(float64)) && hash(p) == f["pack_sha256"], "pack digest")
	check(string(p[:8]) == "OIMOPAK1" && le.Uint16(p[8:10]) == 1 && le.Uint16(p[10:12]) == 256 && le.Uint32(p[12:16]) == 0, "pack header")
	check(le.Uint32(p[252:256]) == crc(p[:252]) && bytes.Equal(p[232:252], make([]byte, 20)), "header CRC")
	check(le.Uint64(p[216:224]) == uint64(len(p)), "pack file length")
	sections := make([][]byte, 5)
	offset := uint64(256)
	for i := 0; i < 5; i++ {
		d := p[96+i*24 : 120+i*24]
		off, n := le.Uint64(d[:8]), le.Uint64(d[8:16])
		check(off == offset && off+n <= uint64(len(p)), "section bounds")
		sections[i] = p[off : off+n]
		check(le.Uint32(d[16:20]) == crc(sections[i]) && le.Uint32(d[20:24]) == 0, "section CRC")
		offset = off + n
	}
	check(offset == uint64(len(p)), "pack EOF")
	meta := jsonObj(sections[0])
	index := sections[1]
	count := int(le.Uint32(p[84:88]))
	check(len(index) == count*96, "index length")
	blockDAT := make([][]byte, count)
	var dat []byte
	var compressed []byte
	compressedSize := 0
	physical := le.Uint64(p[192:200])
	for i := 0; i < count; i++ {
		x := index[i*96 : (i+1)*96]
		check(le.Uint32(x[92:96]) == crc(x[:92]), "index CRC")
		check(le.Uint16(x[42:44]) == 0 && le.Uint32(x[88:92]) == 0, "index reserved")
		check(le.Uint32(x[:4]) == uint32(i+1) && le.Uint32(x[4:8]) == 1 && le.Uint64(x[8:16]) == uint64(len(dat)), "row/DAT ranges")
		off, n, size := le.Uint64(x[24:32]), le.Uint32(x[32:36]), le.Uint32(x[36:40])
		check(off == physical, "block continuity")
		physical += uint64(n)
		stored := p[off : off+uint64(n)]
		check(crc(stored) == le.Uint32(x[44:48]), "stored CRC")
		raw, err := unpack(stored, x[40], int(size))
		check(err == nil, "block decode")
		check(crc(raw) == le.Uint32(x[48:52]), "raw CRC")
		check(string(raw[:8]) == "OIMOBLK1" && le.Uint32(raw[8:12]) == 1 && le.Uint32(raw[12:16]) == 0, "raw block header")
		seq := le.Uint64(raw[16:24])
		check(seq == le.Uint64(x[72:80]) && seq == le.Uint64(x[80:88]), "origin seq")
		jn := int(le.Uint32(raw[24:28]))
		post := jsonObj(raw[28 : 28+jn])
		pos := 28 + jn
		dn := int(le.Uint32(raw[pos : pos+4]))
		row := raw[pos+4:]
		check(dn == len(row) && int(post["dat_length"].(float64)) == dn && post["dat_offset"].(float64) == 0, "row framing")
		check(le.Uint32(x[52:56]) == 1 && num(post["created_at_ns"]) == le.Uint64(x[56:64]) && le.Uint64(x[56:64]) == le.Uint64(x[64:72]), "user time stats")
		check(uint64(len(row)) == le.Uint64(x[16:24]), "DAT block length")
		blockDAT[i] = row
		dat = append(dat, row...)
		if x[40] == 1 {
			compressed = stored
			compressedSize = int(size)
		}
	}
	check(physical == uint64(len(p)), "block end")
	check(bytes.Equal(dat, dec(f["dat_hex"])) && hash(dat) == meta["dat_sha256"] && uint64(len(dat)) == le.Uint64(p[88:96]), "full DAT")
	d := sections[2]
	check(string(d[:8]) == "OIMODED1" && le.Uint32(d[28:32]) == crc(d[:28]), "dedup header")
	entries := int(le.Uint32(d[12:16]))
	check(len(d) == 32+entries*160 && le.Uint64(d[16:24]) == 2, "dedup count")
	for i := 0; i < entries; i++ {
		x := d[32+i*160 : 32+(i+1)*160]
		check(le.Uint32(x[156:160]) == crc(x[:156]) && le.Uint64(x[120:128]) == uint64(i+1), "dedup entry")
	}
	a := sections[3]
	check(string(a[:8]) == "OIMOAUD1" && le.Uint32(a[28:32]) == crc(a[:28]), "audit header")
	chunks := int(le.Uint32(a[24:28]))
	pos, seen := 32, 0
	for i := 0; i < chunks; i++ {
		x := a[pos : pos+24]
		pos += 24
		n := int(le.Uint32(x[8:12]))
		stored := a[pos : pos+n]
		pos += n
		check(crc(stored) == le.Uint32(x[20:24]), "audit stored CRC")
		raw, err := unpack(stored, x[12], int(le.Uint32(x[4:8])))
		check(err == nil && crc(raw) == le.Uint32(x[16:20]), "audit decode")
		rpos := 0
		for j := 0; j < int(le.Uint32(x[:4])); j++ {
			l := int(le.Uint32(raw[rpos : rpos+4]))
			rpos += 4
			record := raw[rpos : rpos+l]
			rpos += l
			check(crc(record) == le.Uint32(raw[rpos:rpos+4]), "audit record CRC")
			rpos += 4
			seen++
			check(num(jsonObj(record)["seq"]) == uint64(seen), "audit seq")
		}
		check(rpos == len(raw), "audit raw EOF")
	}
	check(pos == len(a) && seen == int(le.Uint32(a[12:16])), "audit counts")
	for _, item := range f["ranges"].([]any) {
		r := obj(item)
		start, end := int(r["start"].(float64)), int(r["end"].(float64))
		var actual []byte
		var selected []int
		for i, row := range blockDAT {
			base := int(le.Uint64(index[i*96+8 : i*96+16]))
			lo, hi := max(start, base), min(end, base+len(row))
			if lo < hi {
				actual = append(actual, row[lo-base:hi-base]...)
				selected = append(selected, i+1)
			}
		}
		check(bytes.Equal(actual, dec(r["expected_hex"])) && bytes.Equal(actual, dat[start:end]), "selected block Range")
		want := r["expected_blocks"].([]any)
		check(len(selected) == len(want), "Range block count")
		for i, n := range selected {
			check(n == int(want[i].(float64)), "Range blocks")
		}
	}
	delta := dec(f["delta_hex"])
	check(len(delta) == 64 && le.Uint32(delta[60:64]) == crc(delta[:60]), "empty delta")
	current(f["current_utf8"].(string), p, delta)
	tail := dec(f["delta_with_tail_hex"])
	later := dec(f["delta_after_append_hex"])
	m := current(f["current_with_tail_utf8"].(string), p, tail)
	current(f["current_with_tail_utf8"].(string), p, later)
	prefix := num(obj(m["delta"])["required_end"])
	check(prefix == uint64(len(tail)) && uint64(len(tail)-1) < prefix, "required truncation rejection")
	pos = 64
	seq := uint64(3)
	var extra []byte
	for pos < len(later) {
		n := int(le.Uint32(later[pos : pos+4]))
		check(le.Uint32(later[pos+4:pos+8]) == crc(later[pos:pos+4]), "tail length CRC")
		b := later[pos+8 : pos+8+n]
		check(le.Uint64(b[:8]) == seq && le.Uint32(b[8:12]) == 1, "tail sequence")
		check(le.Uint32(later[pos+8+n:pos+12+n]) == crc(b) && string(later[pos+12+n:pos+20+n]) == "OIMOEND1", "tail frame")
		jn := int(le.Uint32(b[28:32]))
		op := jsonObj(b[32 : 32+jn])
		dn := int(le.Uint32(b[32+jn : 36+jn]))
		row := b[36+jn:]
		check(len(row) == dn && num(op["revision"]) == seq, "tail operation")
		extra = append(extra, row...)
		check(num(obj(op["after"])["dat_bytes"]) == uint64(len(dat)+len(extra)), "tail DAT length")
		pos += n + 20
		if seq == 3 {
			check(uint64(pos) == prefix, "required frame boundary")
		}
		seq++
	}
	check(seq == 5 && bytes.Equal(extra, dec(f["tail_dat_hex"])), "tail DAT/last seq")
	_, e = unpack(append(append([]byte{}, compressed...), compressed...), 1, compressedSize)
	check(e != nil, "reject concatenated gzip")
	_, e = unpack(append(append([]byte{}, compressed...), 0), 1, compressedSize)
	check(e != nil, "reject gzip trailing byte")
	_, e = unpack(compressed, 1, compressedSize-1)
	check(e != nil, "reject gzip output overflow")
	damaged := append([]byte{}, compressed...)
	damaged[len(damaged)-8] ^= 1
	_, e = unpack(damaged, 1, compressedSize)
	check(e != nil, "reject gzip checksum corruption")
	fmt.Println("PASS: pack offsets/CRC/SHA, raw+gzip blocks, compressed audit, 5 DAT ranges, current/prefix stability through seq=4, 4 invalid gzip samples")
}
