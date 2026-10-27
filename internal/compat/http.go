// HTTPの表現選択、条件付き取得、Rangeを設計15の順序で評価する。
package compat

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var codingName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

var quality = regexp.MustCompile(`^(?:0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?)$`)

type ByteRange struct{ Start, End uint64 }

// ParseRange は単一範囲だけを採用する。length=0でも構文有効性を返す。
func ParseRange(s string, length uint64) (r ByteRange, valid, satisfiable bool) {
	if !strings.HasPrefix(s, "bytes=") || strings.Contains(s, ",") {
		return
	}
	v := strings.TrimPrefix(s, "bytes=")
	a, b, ok := strings.Cut(v, "-")
	if !ok || a == "" && b == "" {
		return
	}
	number := func(s string) (uint64, bool) {
		if s == "" {
			return 0, false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, false
			}
		}
		n, e := strconv.ParseUint(s, 10, 64)
		return n, e == nil
	}
	if a == "" {
		n, ok := number(b)
		if !ok {
			return r, false, false
		}
		if n == 0 || length == 0 {
			return r, true, false
		}
		if n > length {
			n = length
		}
		return ByteRange{length - n, length - 1}, true, true
	}
	start, ok := number(a)
	if !ok {
		return
	}
	end := uint64(0)
	if b != "" {
		end, ok = number(b)
		if !ok || start > end {
			return r, false, false
		}
	} else if length > 0 {
		end = length - 1
	}
	if length == 0 || start >= length {
		return r, true, false
	}
	if end >= length {
		end = length - 1
	}
	return ByteRange{start, end}, true, true
}
func encodingQualities(s string) (map[string]float64, error) {
	q := map[string]float64{}
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, param, has := strings.Cut(part, ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if !codingName.MatchString(name) {
			return nil, ErrForm
		}
		v := 1.0
		if has {
			param = strings.TrimSpace(param)
			if !strings.HasPrefix(param, "q=") || !quality.MatchString(param[2:]) {
				return nil, ErrForm
			}
			v, _ = strconv.ParseFloat(param[2:], 64)
		}
		if previous, exists := q[name]; !exists || v > previous {
			q[name] = v
		}
	}
	return q, nil
}

// selectEncoding はq値順、同値はzstdを優先する。
func selectEncoding(header string, p Representation) (identity bool, coding string, err error) {
	// 専ブラの無圧縮取得と単一gzip指定は、q値のmap・正規表現を作らず同じ結果を返す。
	switch header {
	case "", "identity":
		return true, "", nil
	case "gzip":
		return true, "gzip", nil
	}
	q, err := encodingQualities(header)
	if err != nil {
		return false, "", err
	}
	identityQuality := 1.0
	if value, ok := q["identity"]; ok {
		identityQuality = value
	} else if value, ok := q["*"]; ok && value == 0 {
		identityQuality = 0
	}
	identity = identityQuality > 0
	best := identityQuality
	candidates := []string{"zstd", "gzip"}
	for _, candidate := range candidates {
		if candidate != "gzip" && (p.Compress == nil || p.codingTag(candidate) == "") {
			continue
		}
		value, ok := q[candidate]
		if !ok {
			value = q["*"]
		}
		if value > 0 && (value > best || value == best && coding == "") {
			best = value
			coding = candidate
		}
	}
	return identity, coding, nil
}

// codingTag は圧縮規則ごとの強いETagを返す。
func (p Representation) codingTag(coding string) string {
	switch coding {
	case "gzip":
		return p.ETagGzip
	case "zstd":
		return p.ETagZstd
	}
	return p.ETagIdentity
}

func tagMatch(header, tag string, weak bool) bool {
	for s := range strings.SplitSeq(header, ",") {
		s = strings.TrimSpace(s)
		if s == "*" {
			return true
		}
		if weak {
			s = strings.TrimPrefix(s, "W/")
			tag = strings.TrimPrefix(tag, "W/")
		}
		if s == tag {
			return true
		}
	}
	return false
}

// Representation は公開本文と表現ごとの検証子。圧縮は条件評価後にだけ呼ばれる。
type Representation struct {
	ContentType                              string
	Compress                                 func(context.Context, string, string, []byte) ([]byte, error)
	ETagZstd                                 string
	DisableRange                             bool
	DAT                                      []byte
	ETagIdentity, ETagGzip                   string
	Modified, Now                            time.Time
	DateSafe, DateExact, LegacyRangeDisabled bool
}

// ServeDAT は実HTTPの200/206/304/406/412/416とHEADを返す。
func ServeDAT(w http.ResponseWriter, r *http.Request, p Representation) {
	h := w.Header()
	h.Set("Vary", "Accept-Encoding")
	h.Set("Cache-Control", "no-cache")
	contentType := p.ContentType
	if contentType == "" {
		contentType = "text/plain; charset=Shift_JIS"
	}
	h.Set("Content-Type", contentType)
	identity, coding, e := selectEncoding(strings.Join(r.Header.Values("Accept-Encoding"), ","), p)
	if e != nil {
		w.WriteHeader(400)
		return
	}
	br, valid, sat := ParseRange(r.Header.Get("Range"), uint64(len(p.DAT)))
	useRange := !p.DisableRange && r.Method == "GET" && valid && identity
	useCompressed := !useRange && coding != "" && (len(p.DAT) >= 200 || !identity)
	if !useCompressed && !identity {
		w.WriteHeader(406)
		return
	}
	tag := p.ETagIdentity
	if useCompressed {
		tag = p.codingTag(coding)
		h.Set("Content-Encoding", coding)
	}
	h.Set("ETag", tag)
	if !p.DisableRange {
		h.Set("Accept-Ranges", "bytes")
	}
	dateSafe := p.DateSafe && !p.LegacyRangeDisabled && p.Modified.Unix() < p.Now.Unix()
	if dateSafe {
		h.Set("Last-Modified", p.Modified.UTC().Format(http.TimeFormat))
	}
	if match := r.Header.Get("If-Match"); match != "" {
		if !tagMatch(match, tag, false) {
			w.WriteHeader(412)
			return
		}
	} else if s := r.Header.Get("If-Unmodified-Since"); dateSafe && s != "" {
		if d, e := http.ParseTime(s); e == nil && p.Modified.Unix() > d.Unix() {
			w.WriteHeader(412)
			return
		}
	}
	if none := r.Header.Get("If-None-Match"); none != "" {
		if tagMatch(none, tag, true) {
			notModified(w)
			return
		}
	} else if s := r.Header.Get("If-Modified-Since"); dateSafe && s != "" {
		if d, e := http.ParseTime(s); e == nil && (d.Unix() > p.Modified.Unix() || p.DateExact && d.Unix() == p.Modified.Unix()) && d.Unix() <= p.Now.Unix() {
			notModified(w)
			return
		}
	}
	if useRange {
		ir := r.Header.Get("If-Range")
		matches := ir == tag
		if !matches && dateSafe && p.DateExact && ir != "" {
			date, err := http.ParseTime(ir)
			matches = err == nil && date.Unix() == p.Modified.Unix()
		}
		if ir != "" && !matches || p.LegacyRangeDisabled && ir != tag {
			useRange = false
		}
	}
	body := p.DAT
	status := 200
	if useRange {
		if !sat {
			h.Set("Content-Range", fmt.Sprintf("bytes */%d", len(body)))
			w.WriteHeader(416)
			return
		}
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", br.Start, br.End, len(body)))
		body = body[br.Start : br.End+1]
		status = 206
	} else if useCompressed {
		// cold HEADは圧縮せず、未確定の圧縮長を省略する（設計15）。
		if r.Method == "HEAD" {
			w.WriteHeader(status)
			return
		}
		if p.Compress != nil {
			body, e = p.Compress(r.Context(), coding, tag, body)
		} else {
			body = compressGzip(body)
		}
		if e != nil {
			h.Del("Content-Encoding")
			h.Del("ETag")
			h.Set("Retry-After", "1")
			w.WriteHeader(503)
			return
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != "HEAD" {
		if writer, ok := w.(interface {
			WriteResponse(int, []byte) (int, error)
		}); ok {
			_, _ = writer.WriteResponse(status, body)
			return
		}
	}
	w.WriteHeader(status)
	if r.Method != "HEAD" {
		_, _ = w.Write(body)
	}
}

// notModified は検証子を維持し、本文のない再検証に不要なメタデータを省く。
func notModified(w http.ResponseWriter) {
	for _, key := range []string{"Content-Type", "Content-Encoding", "Content-Length", "Accept-Ranges"} {
		w.Header().Del(key)
	}
	w.WriteHeader(http.StatusNotModified)
}
