// 許可ヘッダのパーサ値だけを記録し、Originはscheme/host/portへ制限する。
package evidence

import (
	"encoding/base64"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const MaxObservedHeaderBytes = 16 << 10

var selectedHeaderNames = []string{"Accept-Language", "Content-Encoding", "Content-Type", "Origin", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "User-Agent"}
var reportedHeaderNames = []string{"Forwarded", "X-Forwarded-For", "X-Oimo-Client-Ip", "X-Oimo-Client-Port", "X-Oimo-Destination-Ip", "X-Oimo-Destination-Port", "X-Oimo-Edge-Request-Id", "X-Oimo-Edge-Time", "X-Real-Ip"}

func captureHeaders(headers http.Header, host string) ([]ObservedHeader, []ObservedHeader, int, error) {
	size := len("Host: \r\n") + len(host)
	normalized := map[string][]string{}
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if _, exists := normalized[canonical]; exists {
			return nil, nil, 0, ErrHTTPObservation
		}
		normalized[canonical] = values
		for _, value := range values {
			size += len(name) + len(value) + 4
			if size > MaxObservedHeaderBytes {
				return nil, nil, 0, ErrHTTPObservation
			}
		}
	}
	if size > MaxObservedHeaderBytes {
		return nil, nil, 0, ErrHTTPObservation
	}
	collect := func(names []string) ([]ObservedHeader, error) {
		result := []ObservedHeader{}
		for _, name := range names {
			values, exists := normalized[name]
			if !exists {
				continue
			}
			if len(values) == 0 {
				return nil, ErrHTTPObservation
			}
			h := ObservedHeader{Name: name, Representation: "http_parser", Values: []HeaderValue{}}
			for _, value := range values {
				if name == "Origin" {
					var e error
					value, e = originOnly(value)
					if e != nil {
						return nil, e
					}
					h.Representation = "origin_only"
				}
				h.Values = append(h.Values, encodeHeaderValue(value))
			}
			result = append(result, h)
		}
		return result, nil
	}
	selected, e := collect(selectedHeaderNames)
	if e != nil {
		return nil, nil, 0, e
	}
	reported, e := collect(reportedHeaderNames)
	return selected, reported, size, e
}
func encodeHeaderValue(value string) HeaderValue {
	return HeaderValue{base64.StdEncoding.EncodeToString([]byte(value)), strings.ToValidUTF8(value, "\uFFFD")}
}
func decodeHeaderValue(value HeaderValue) (string, error) {
	raw, e := base64.StdEncoding.Strict().DecodeString(value.Base64)
	if e != nil || base64.StdEncoding.EncodeToString(raw) != value.Base64 || strings.ToValidUTF8(string(raw), "\uFFFD") != value.Display {
		return "", ErrHTTPObservation
	}
	for _, b := range raw {
		if b < 32 && b != '\t' || b == 127 {
			return "", ErrHTTPObservation
		}
	}
	return string(raw), nil
}
func originOnly(value string) (string, error) {
	if value == "null" {
		return value, nil
	}
	u, e := url.Parse(value)
	if e != nil || u.Opaque != "" || u.Scheme != "http" && u.Scheme != "https" || !validAuthority(strings.ToLower(u.Host)) {
		return "", ErrHTTPObservation
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

// validateObservedContentType は入力の妥当性だけを確認し、文字コードの重複項目は保存しない。
func validateObservedContentType(headers []ObservedHeader) error {
	for _, h := range headers {
		if h.Name != "Content-Type" {
			continue
		}
		if len(h.Values) != 1 {
			return ErrHTTPObservation
		}
		raw, e := decodeHeaderValue(h.Values[0])
		if e != nil {
			return e
		}
		_, parameters, e := mime.ParseMediaType(raw)
		if e != nil {
			return ErrHTTPObservation
		}
		charset, exists := parameters["charset"]
		if !exists {
			return nil
		}
		charset = strings.ToLower(charset)
		if !validLabel(charset, 64) {
			return ErrHTTPObservation
		}
		return nil
	}
	return nil
}
func validateHeaders(headers []ObservedHeader, allowed []string) (int, error) {
	if headers == nil {
		return 0, ErrHTTPObservation
	}
	previous := ""
	size := 0
	for _, h := range headers {
		if !slices.Contains(allowed, h.Name) || h.Name <= previous || len(h.Values) == 0 {
			return 0, ErrHTTPObservation
		}
		previous = h.Name
		representation := "http_parser"
		if h.Name == "Origin" {
			representation = "origin_only"
		}
		if h.Representation != representation {
			return 0, ErrHTTPObservation
		}
		for _, value := range h.Values {
			raw, e := decodeHeaderValue(value)
			if e != nil {
				return 0, e
			}
			if h.Name == "Origin" {
				origin, e := originOnly(raw)
				if e != nil || origin != raw {
					return 0, ErrHTTPObservation
				}
			}
			size += len(h.Name) + len(raw) + 4
			if size > MaxObservedHeaderBytes {
				return 0, ErrHTTPObservation
			}
		}
	}
	return size, nil
}
