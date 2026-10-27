// 国別archiveを有界に読み、独立したJSONの解析を利用可能なコアへ配分する。
package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"runtime"
	"strings"
	"sync/atomic"
)

// parseCountryArchive は展開済みarchive全体の複製を避け、gzip末尾のCRCも検査する。
func parseCountryArchive(ctx context.Context, raw []byte) ([]identity.CountryNetwork, error) {
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errNetworkData
	}
	defer z.Close()
	input := &io.LimitedReader{R: z, N: (32 << 20) + 1}
	archive := tar.NewReader(input)
	jobs := []func() error{}
	results := []*[]identity.CountryNetwork{}
	seen := map[string]bool{}
	var reserved atomic.Int64
	for files := 0; ; files++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, e := archive.Next()
		if e == io.EOF {
			break
		}
		if e != nil || files >= 10000 {
			return nil, errNetworkData
		}
		parts := strings.Split(h.Name, "/")
		if len(parts) != 4 || parts[1] != "country" || parts[3] != "aggregated.json" {
			continue
		}
		code := strings.ToUpper(parts[2])
		if !identity.ValidCountryCode(code) || strings.ToLower(code) != parts[2] || seen[code] || h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > 1<<20 {
			return nil, errNetworkData
		}
		seen[code] = true
		body := make([]byte, int(h.Size))
		if _, e = io.ReadFull(archive, body); e != nil {
			return nil, errNetworkData
		}
		result := new([]identity.CountryNetwork)
		results = append(results, result)
		jobs = append(jobs, func() error { var e error; *result, e = parseCountryJSON(body, code, &reserved); return e })
	}
	// tarの終端で読むのを止めると、その後の膨張やgzip破損を見逃す。
	if _, err = io.Copy(io.Discard, input); err != nil || input.N == 0 || len(seen) < 2 {
		return nil, errNetworkData
	}
	for _, err := range runNetworkJobsLimit(ctx, jobs, min(4, runtime.GOMAXPROCS(0))) {
		if err != nil {
			return nil, err
		}
	}
	count := 0
	for _, result := range results {
		count += len(*result)
		if count > countryRowLimit {
			return nil, errNetworkData
		}
	}
	rows := make([]identity.CountryNetwork, 0, count)
	for _, result := range results {
		rows = append(rows, (*result)...)
	}
	return rows, nil
}

// parseCountryJSON は未知のmetadataを許容し、国コード・family・正規CIDRは厳密に検査する。
func parseCountryJSON(body []byte, expected string, reserved *atomic.Int64) ([]identity.CountryNetwork, error) {
	var fields map[string]json.RawMessage
	if strictjson.Decode(body, &fields) != nil {
		return nil, errNetworkData
	}
	var code string
	if json.Unmarshal(fields["countryCode"], &code) != nil || code != expected {
		return nil, errNetworkData
	}
	var prefixes struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	}
	if strictjson.Decode(fields["prefixes"], &prefixes) != nil || prefixes.IPv4 == nil || prefixes.IPv6 == nil {
		return nil, errNetworkData
	}
	if reserved.Add(int64(len(prefixes.IPv4)+len(prefixes.IPv6))) > countryRowLimit {
		return nil, errNetworkData
	}
	rows := make([]identity.CountryNetwork, 0, len(prefixes.IPv4)+len(prefixes.IPv6))
	for _, family := range []struct {
		v4     bool
		values []string
	}{{true, prefixes.IPv4}, {false, prefixes.IPv6}} {
		for _, cidr := range family.values {
			p, err := netip.ParsePrefix(cidr)
			if err != nil || p.Addr().Is4() != family.v4 || p.String() != cidr || p != p.Masked() {
				return nil, errNetworkData
			}
			rows = append(rows, identity.CountryNetwork{Prefix: p, Code: code})
		}
	}
	return rows, nil
}
