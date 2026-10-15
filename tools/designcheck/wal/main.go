// 設計fixtureの配置とCRCを標準Goで独立照合する確認プログラム。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
	"time"
)

var le = binary.LittleEndian
var tab = crc32.MakeTable(crc32.Castagnoli)

func check(b bool, s string) {
	if !b {
		panic(s)
	}
}
func obj(v any) map[string]any { return v.(map[string]any) }
func decode(v any) []byte {
	b, e := hex.DecodeString(v.(string))
	if e != nil {
		panic(e)
	}
	return b
}
func num(v any) uint64 {
	n, e := strconv.ParseUint(v.(string), 10, 64)
	if e != nil {
		panic(e)
	}
	return n
}
func crc(b []byte) uint32 { return crc32.Checksum(b, tab) }
func read(p string) map[string]any {
	b, e := os.ReadFile(p)
	if e != nil {
		panic(e)
	}
	var v map[string]any
	if e = json.Unmarshal(b, &v); e != nil {
		panic(e)
	}
	return v
}
func main() {
	check(crc([]byte("123456789")) == 0xe3069283, "known CRC32C")
	v := read("docs/design/fixtures/wal-v1-layout.json")
	ho := obj(v["wal_header"])
	h := decode(ho["hex"])
	check(len(h) == 64 && string(h[:8]) == "OIMOWAL1", "header size/magic")
	check(le.Uint16(h[8:10]) == 1 && le.Uint16(h[10:12]) == 64 && le.Uint32(h[12:16]) == 0, "header version")
	check(bytes.Equal(h[16:32], decode(ho["board_id_hex"])) && le.Uint64(h[32:40]) == num(ho["thread_key"]), "header identity")
	check(le.Uint64(h[40:48]) == num(ho["base_seq"]) && le.Uint64(h[48:56]) == num(ho["storage_generation"]), "header sequences")
	check(le.Uint32(h[56:60]) == 0 && le.Uint32(h[60:]) == crc(h[:60]), "header CRC")
	fo := obj(v["frame"])
	f := decode(fo["hex"])
	n := int(le.Uint32(f[:4]))
	check(n+20 == len(f) && n == int(fo["body_length"].(float64)), "frame lengths")
	check(le.Uint32(f[4:8]) == crc(f[:4]), "length CRC")
	b := f[8 : 8+n]
	check(le.Uint32(f[8+n:12+n]) == crc(b) && string(f[12+n:]) == "OIMOEND1", "trailer")
	check(le.Uint64(b[:8]) == num(fo["first_seq"]) && le.Uint32(b[8:12]) == 1, "frame sequence")
	check(bytes.Equal(b[12:28], decode(fo["operation_id_hex"])), "operation ID")
	jn := int(le.Uint32(b[28:32]))
	check(string(b[32:32+jn]) == fo["json_utf8"].(string), "JSON")
	check(le.Uint32(b[32+jn:36+jn]) == 0 && len(b) == 36+jn, "DAT boundary")
	check(fo["valid_operation_schema"] == false, "envelope only")
	digest := sha256.Sum256(append(append([]byte{}, h...), f...))
	check(hex.EncodeToString(digest[:]) == v["wal_envelope_sha256"], "SHA256")
	d := obj(v["dedup_section"])
	dh := decode(d["header_hex"])
	e := decode(d["entry_hex"])
	check(len(dh) == 32 && string(dh[:8]) == "OIMODED1" && le.Uint16(dh[8:10]) == 1 && le.Uint16(dh[10:12]) == 32, "dedup header")
	check(le.Uint32(dh[12:16]) == 1 && le.Uint64(dh[16:24]) == 7 && le.Uint16(dh[24:26]) == 160 && le.Uint16(dh[26:28]) == 0, "dedup layout")
	check(le.Uint32(dh[28:]) == crc(dh[:28]), "dedup header CRC")
	check(len(e) == 160 && e[0] == 1 && e[1] == 1 && le.Uint16(e[2:4]) == 0 && le.Uint32(e[4:8]) == 1, "entry header")
	check(bytes.Equal(e[8:40], bytes.Repeat([]byte{0x11}, 32)) && bytes.Equal(e[40:72], bytes.Repeat([]byte{0x22}, 32)) && bytes.Equal(e[72:104], bytes.Repeat([]byte{0x33}, 32)), "entry hashes")
	check(bytes.Equal(e[104:120], decode(fo["operation_id_hex"])) && le.Uint64(e[120:128]) == 7 && le.Uint32(e[128:132]) == 1, "entry receipt")
	check(le.Uint32(e[132:136]) == 0 && le.Uint32(e[152:156]) == 0 && le.Uint32(e[156:]) == crc(e[:156]), "entry CRC")
	check(int64(le.Uint64(e[144:152]))-int64(le.Uint64(e[136:144])) == int64(24*time.Hour), "entry expiry")
	c := read("docs/design/fixtures/wal-v1-create.json")
	co := obj(c["operation"])
	dat := decode(c["dat_hex"])
	a := obj(co["after"])
	p := obj(co["payload"])
	check(co["type"] == "create" && num(co["revision"]) == 1 && num(a["dat_bytes"]) == uint64(len(dat)), "create metadata")
	check(bytes.Count(dat, []byte("<>")) == 4 && bytes.Count(dat, []byte{'\n'}) == 1 && dat[len(dat)-1] == '\n', "create DAT")
	posts := p["posts"].([]any)
	post := obj(posts[0])
	check(len(posts) == 1 && post["dat_offset"].(float64) == 0 && int(post["dat_length"].(float64)) == len(dat), "create post")
	ct := int64(num(co["committed_at_ns"]))
	ex := int64(num(p["expires_at_ns"]))
	zone := time.FixedZone("JST", 9*60*60)
	check(time.Unix(0, ct).In(zone).AddDate(0, 6, 0).UnixNano() == ex, "sample six months")
	check(int64(num(obj(co["dedup"])["expires_at_ns"]))-ct == int64(24*time.Hour), "create dedup expiry")
	fmt.Println("PASS: standard Go CRC32C, header/frame offsets, dedup section, create DAT lengths and sample expiry")
}
