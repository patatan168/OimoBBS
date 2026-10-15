// 設計用の合成fixtureを標準Goで照合する。サーバ実装・完全な形式検証器ではない。
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var le = binary.LittleEndian
var table = crc32.MakeTable(crc32.Castagnoli)

func must(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func crc(b []byte) uint32  { return crc32.Checksum(b, table) }
func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func dec(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func read(name string, v any) {
	b, e := os.ReadFile("docs/design/fixtures/" + name)
	if e != nil {
		panic(e)
	}
	if e = json.Unmarshal(b, v); e != nil {
		panic(e)
	}
}

// controlFrameは外枠とseqの局所検査だけを行う。collectionの全業務制約は対象外。
func controlFrame(h, f []byte) error {
	if len(h) != 64 || string(h[:8]) != "OIMOCTL1" || le.Uint16(h[8:10]) != 1 || le.Uint16(h[10:12]) != 64 || le.Uint16(h[12:14]) != 2 || le.Uint16(h[14:16]) != 0 || le.Uint32(h[56:60]) != 0 || crc(h[:60]) != le.Uint32(h[60:]) {
		return errors.New("header")
	}
	if len(f) < 58 {
		return errors.New("short frame")
	}
	n := uint64(le.Uint32(f[:4]))
	if n > 8<<20 || n+20 != uint64(len(f)) || crc(f[:4]) != le.Uint32(f[4:8]) {
		return errors.New("length")
	}
	b := f[8 : 8+n]
	if crc(b) != le.Uint32(f[8+n:12+n]) || string(f[12+n:]) != "OIMOEND1" {
		return errors.New("trailer")
	}
	if le.Uint64(b[:8]) != le.Uint64(h[40:48])+1 || le.Uint32(b[8:12]) != 1 {
		return errors.New("sequence")
	}
	jn := uint64(le.Uint32(b[28:32]))
	if jn > 1<<20 || jn+36 != uint64(len(b)) || le.Uint32(b[32+jn:36+jn]) != 0 {
		return errors.New("json/dat")
	}
	var op struct {
		Seq       string            `json:"seq"`
		Expected  string            `json:"expected_seq"`
		Mutations []json.RawMessage `json:"mutations"`
	}
	if e := json.Unmarshal(b[32:32+jn], &op); e != nil {
		return e
	}
	if op.Seq != strconv.FormatUint(le.Uint64(b[:8]), 10) || op.Expected != strconv.FormatUint(le.Uint64(h[40:48]), 10) || len(op.Mutations) != 1 {
		return errors.New("record")
	}
	return nil
}

func verifyControl() {
	var f struct {
		Header   string          `json:"header_hex"`
		Frame    string          `json:"frame_hex"`
		Snapshot string          `json:"snapshot_hex"`
		Delta    string          `json:"empty_delta_hex"`
		Current  string          `json:"current_utf8"`
		Record   json.RawMessage `json:"record"`
		Row      json.RawMessage `json:"row"`
	}
	read("control-v1-layout.json", &f)
	h, b, s, d := dec(f.Header), dec(f.Frame), dec(f.Snapshot), dec(f.Delta)
	must(controlFrame(h, b) == nil, "control frame")
	jn := int(le.Uint32(b[36:40]))
	var actual, expected any
	must(json.Unmarshal(b[40:40+jn], &actual) == nil && json.Unmarshal(f.Record, &expected) == nil && reflect.DeepEqual(actual, expected), "control JSON")
	must(len(s) >= 96 && string(s[:8]) == "OIMOCSN1" && le.Uint64(s[40:48]) == 2 && le.Uint32(s[56:60]) == 1 && crc(s[:60]) == le.Uint32(s[60:64]), "snapshot header")
	ch, raw := s[64:96], s[96:]
	must(string(ch[:8]) == "OIMOCBK1" && int(le.Uint32(ch[8:12])) == len(raw) && int(le.Uint32(ch[12:16])) == len(raw) && le.Uint32(ch[16:20]) == 1 && bytes.Equal(ch[20:24], []byte{0, 0, 0, 0}), "snapshot chunk")
	must(crc(raw) == le.Uint32(ch[24:28]) && crc(raw) == le.Uint32(ch[28:32]), "snapshot CRC")
	must(int(le.Uint32(raw[:4]))+4 == len(raw), "snapshot row size")
	must(json.Unmarshal(raw[4:], &actual) == nil && json.Unmarshal(f.Row, &expected) == nil && reflect.DeepEqual(actual, expected), "snapshot row JSON")
	var cur struct {
		Manifest json.RawMessage `json:"manifest"`
		SHA      string          `json:"manifest_sha256"`
	}
	must(json.Unmarshal([]byte(f.Current), &cur) == nil && hash(cur.Manifest) == cur.SHA, "control exact manifest")
	var m struct {
		Kind       int    `json:"kind"`
		Owner      string `json:"owner_id"`
		Generation string `json:"generation"`
		Snapshot   struct {
			SHA    string `json:"sha256"`
			Length string `json:"length"`
			Seq    string `json:"seq"`
		} `json:"snapshot"`
		Delta struct {
			Base string `json:"base_seq"`
			Seq  string `json:"required_seq"`
			End  string `json:"required_end"`
			SHA  string `json:"required_sha256"`
		} `json:"delta"`
	}
	must(json.Unmarshal(cur.Manifest, &m) == nil, "manifest JSON")
	must(m.Kind == 2 && bytes.Equal(dec(m.Owner), h[16:32]) && m.Generation == "3" && m.Snapshot.SHA == hash(s) && m.Snapshot.Length == strconv.Itoa(len(s)) && m.Snapshot.Seq == "2", "snapshot reference")
	must(len(d) == 64 && crc(d[:60]) == le.Uint32(d[60:]) && le.Uint64(d[40:48]) == 2 && m.Delta.Base == "2" && m.Delta.Seq == "2" && m.Delta.End == "64" && m.Delta.SHA == hash(d), "empty control delta")
	bad := append([]byte(nil), b...)
	bad[40] ^= 1
	must(controlFrame(h, bad) != nil, "reject corrupt JSON CRC")
	must(controlFrame(h, b[:len(b)-1]) != nil, "reject truncated frame")
	badh := append([]byte(nil), h...)
	le.PutUint64(badh[40:48], 3)
	le.PutUint32(badh[60:], crc(badh[:60]))
	must(controlFrame(badh, b) != nil, "reject wrong base sequence")
	badh = append([]byte(nil), h...)
	le.PutUint16(badh[12:14], 1)
	le.PutUint32(badh[60:], crc(badh[:60]))
	must(controlFrame(badh, b) != nil, "reject other owner kind")
	fmt.Println("PASS: control frame/snapshot/current bytes, CRC/SHA, JSON equality, 4 invalid control examples")
}

type request struct {
	Method   string `json:"method"`
	Length   int    `json:"length"`
	Accept   string `json:"accept"`
	Range    string `json:"range"`
	Match    string `json:"if_match"`
	None     string `json:"if_none_match"`
	IfRange  string `json:"if_range"`
	Disabled bool   `json:"legacy_range_disabled"`
	State    string `json:"public_state"`
}
type result struct {
	Status         int     `json:"status"`
	Representation *string `json:"representation"`
	Range          []int   `json:"range"`
}

func str(s string) *string { return &s }

// parseRangeは設計判断表用。HTTPヘッダの全パーサを代替しない。
func parseRange(s string, length int) (valid bool, lo, hi int) {
	if !strings.HasPrefix(s, "bytes=") || strings.Contains(s, ",") {
		return false, 0, 0
	}
	x := strings.Split(strings.TrimPrefix(s, "bytes="), "-")
	if len(x) != 2 || x[0] == "" && x[1] == "" {
		return false, 0, 0
	}
	parse := func(s string) (uint64, error) {
		if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return 0, errors.New("integer")
		}
		return strconv.ParseUint(s, 10, 64)
	}
	if x[0] == "" {
		n, e := parse(x[1])
		if e != nil {
			return false, 0, 0
		}
		if n == 0 || length == 0 {
			return true, length, length - 1
		}
		if n >= uint64(length) {
			return true, 0, length - 1
		}
		return true, length - int(n), length - 1
	}
	a, e := parse(x[0])
	if e != nil {
		return false, 0, 0
	}
	z := uint64(max(0, length-1))
	if x[1] != "" {
		z, e = parse(x[1])
		if e != nil || a > z {
			return false, 0, 0
		}
	}
	if a >= uint64(length) {
		return true, length, length - 1
	}
	return true, int(a), int(min(z, uint64(length-1)))
}
func encoding(a string) (gzipOK, identityOK, valid bool) {
	if a == "" {
		return false, true, true
	}
	q := map[string]float64{}
	for _, part := range strings.Split(a, ",") {
		items := strings.Split(strings.TrimSpace(part), ";")
		if len(items) > 2 || items[0] == "" {
			return false, false, false
		}
		v := 1.0
		if len(items) == 2 {
			p := strings.TrimSpace(items[1])
			if !strings.HasPrefix(p, "q=") {
				return false, false, false
			}
			n := strings.TrimPrefix(p, "q=")
			var e error
			v, e = strconv.ParseFloat(n, 64)
			if e != nil || v < 0 || v > 1 {
				return false, false, false
			}
			if p := strings.IndexByte(n, '.'); p >= 0 && len(n)-p-1 > 3 {
				return false, false, false
			}
		}
		q[items[0]] = v
	}
	g, hasG := q["gzip"]
	star, hasStar := q["*"]
	if !hasG && hasStar {
		g = star
	}
	i, hasI := q["identity"]
	if !hasI {
		i = 1
		if hasStar && star == 0 {
			i = 0
		}
	}
	return g > 0, i > 0, true
}
func tagMatches(list, tag string, weak bool) bool {
	for _, t := range strings.Split(list, ",") {
		t = strings.TrimSpace(t)
		if t == "*" {
			return true
		}
		if weak {
			t = strings.TrimPrefix(t, "W/")
		}
		if t == tag {
			return true
		}
	}
	return false
}
func decide(r request) result {
	if r.State == "hidden" {
		return result{Status: 410}
	}
	g, i, ok := encoding(r.Accept)
	if !ok {
		return result{Status: 400}
	}
	if !g && !i {
		return result{Status: 406}
	}
	valid, lo, hi := parseRange(r.Range, r.Length)
	valid = valid && r.Method == "GET"
	rep := "identity"
	if !(valid && i) && g && (r.Length >= 200 || !i) {
		rep = "gzip"
	}
	res := result{Status: 200, Representation: str(rep)}
	tag := "\"" + rep + "\""
	if r.Match != "" && !tagMatches(r.Match, tag, false) {
		res.Status = 412
		return res
	}
	if tagMatches(r.None, tag, true) {
		res.Status = 304
		return res
	}
	if valid && i && (!r.Disabled || r.IfRange == tag) && (r.IfRange == "" || r.IfRange == tag) {
		if lo > hi {
			res.Status = 416
		} else {
			res.Status = 206
			res.Range = []int{lo, hi}
		}
	}
	return res
}
func verifyHTTP() {
	var f struct {
		Cases []struct {
			ID       string  `json:"id"`
			Request  request `json:"request"`
			Expected result  `json:"expected"`
		} `json:"cases"`
	}
	read("http-decisions.json", &f)
	for _, c := range f.Cases {
		got := decide(c.Request)
		must(reflect.DeepEqual(got, c.Expected), fmt.Sprintf("HTTP %s got=%+v expected=%+v", c.ID, got, c.Expected))
	}
	fmt.Printf("PASS: %d HTTP decision examples (not a live HTTP server)\n", len(f.Cases))
}
func lp(b []byte) []byte {
	out := make([]byte, 4, len(b)+4)
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}
func mac(key []byte, domain string, fields ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(lp([]byte(domain)))
	for _, f := range fields {
		h.Write(lp(f))
	}
	return h.Sum(nil)
}
func verifyIdentity() {
	var f struct {
		Key     string `json:"key_hex"`
		Board   string `json:"board_hex"`
		Day     string `json:"day"`
		IP      string `json:"canonical_ip_hex"`
		ID      string `json:"daily_id"`
		Payload string `json:"token_payload_hex"`
		Token   string `json:"token"`
		Months  []struct {
			Created string `json:"created"`
			Expires string `json:"expires"`
		} `json:"six_months"`
	}
	read("identity-and-time.json", &f)
	key := dec(f.Key)
	digest := mac(key, "oimo/id/v1", dec(f.Board), []byte(f.Day), dec(f.IP))
	must(base64.StdEncoding.EncodeToString(digest)[:8] == f.ID, "daily ID HMAC")
	p := dec(f.Payload)
	must(len(p) == 48, "anon payload size")
	want := "v3.7." + base64.RawURLEncoding.EncodeToString(p) + "." + base64.RawURLEncoding.EncodeToString(mac(key, "oimo/anon/v3", []byte("7"), p))
	must(want == f.Token, "anon token MAC")
	altered := append([]byte(nil), p...)
	altered[0] ^= 1
	must(!hmac.Equal(mac(key, "oimo/anon/v3", []byte("7"), p), mac(key, "oimo/anon/v3", []byte("7"), altered)), "token tamper changes MAC")
	zone := time.FixedZone("JST", 9*3600)
	for _, m := range f.Months {
		t, e := time.Parse(time.RFC3339, m.Created)
		must(e == nil, "created time")
		t = t.In(zone)
		first := time.Date(t.Year(), t.Month()+6, 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), zone)
		last := time.Date(first.Year(), first.Month()+1, 0, 0, 0, 0, 0, zone).Day()
		expires := time.Date(first.Year(), first.Month(), min(t.Day(), last), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), zone)
		must(expires.Format(time.RFC3339) == m.Expires, "six month clamp")
	}
	fmt.Println("PASS: independent HMAC ID/token vector, token tamper, 3 six-calendar-month boundaries")
}
func main() { verifyControl(); verifyHTTP(); verifyIdentity() }
