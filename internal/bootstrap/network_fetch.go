// 公開HTTPSの有界取得とCSV/ASN検査を行い、一部成功の分類表を公開しない。
package bootstrap

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errNetworkFetch = errors.New("network fetch failed")
var errNetworkData = errors.New("invalid network data")

// newNetworkClient はproxyを使わず公開IPへだけ接続する。redirectも同じHTTPS条件で検査する。
func newNetworkClient() *http.Client {
	transport := &http.Transport{TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 8, IdleConnTimeout: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialNetworkAddress(ctx, network, address, net.DefaultResolver.LookupNetIP, (&net.Dialer{Timeout: 5 * time.Second}).DialContext)
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || !validNetworkURL(req.URL.String()) {
			return errNetworkFetch
		}
		return nil
	}}
}

// fetchNetworkBody は許可したHTTPS URLの成功本文だけを4MiBまで読み、応答を必ず閉じる。
func fetchNetworkBody(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	if !validNetworkURL(target) {
		return nil, errNetworkFetch
	}
	req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
	if e != nil {
		return nil, errNetworkFetch
	}
	req.Header.Set("User-Agent", "OimoBBS-network-updater/1")
	res, e := client.Do(req)
	if e != nil {
		return nil, errNetworkFetch
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errNetworkFetch
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
	if e != nil || len(raw) > 4<<20 {
		return nil, errNetworkFetch
	}
	return raw, nil
}

// fetchNetworkRows は全取得元を検査し、分類衝突を不明化して空集合・容量超過を拒否する。
func fetchNetworkRows(ctx context.Context, client *http.Client, sources []NetworkSource) ([]identity.NetworkClass, error) {
	if len(sources) > networkSourceLimit {
		return nil, errNetworkData
	}
	return mergeNetworkBatches(fetchNetworkBatches(ctx, client, sources), sources)
}

// mergeNetworkBatches は取得順によらず同じ衝突検査と保存順を適用する。
func mergeNetworkBatches(batches []networkBatch, sources []NetworkSource) ([]identity.NetworkClass, error) {
	rows := []identity.NetworkClass{}
	seen := map[string]identity.NetworkClass{}
	for _, result := range batches {
		if result.err != nil {
			return nil, result.err
		}
		batch := result.rows
		for _, r := range batch {
			if old, ok := seen[r.CIDR]; ok {
				merged, ok := mergeAutomaticNetwork(old, r)
				if !ok {
					return nil, errNetworkData
				}
				seen[r.CIDR] = merged
				continue
			}
			rows = append(rows, r)
			seen[r.CIDR] = r
			if len(rows) > networkRowLimit {
				return nil, errNetworkData
			}
		}
	}
	if len(rows) == 0 && !hasAccessSources(sources) {
		return nil, errNetworkData
	}
	if _, e := identity.CompileNetworks(rows, networkRowLimit); e != nil {
		return nil, errNetworkData
	}
	rows = rows[:0]
	for _, row := range seen {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CIDR < rows[j].CIDR })
	raw, _ := json.Marshal(rows)
	if len(raw) > 6<<20 {
		return nil, errNetworkData
	}
	return rows, nil
}

func parseASNNetworks(raw []byte, s NetworkSource) ([]identity.NetworkClass, error) {
	var fields map[string]json.RawMessage
	if strictjson.Decode(raw, &fields) != nil {
		return nil, errNetworkData
	}
	var asn uint32
	if json.Unmarshal(fields["asn"], &asn) != nil || asn != s.ASN {
		return nil, errNetworkData
	}
	var prefixes struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	}
	if strictjson.Decode(fields["prefixes"], &prefixes) != nil || prefixes.IPv4 == nil || prefixes.IPv6 == nil {
		return nil, errNetworkData
	}
	rows := []identity.NetworkClass{}
	for _, family := range []struct {
		values []string
		v4     bool
	}{{prefixes.IPv4, true}, {prefixes.IPv6, false}} {
		for _, cidr := range family.values {
			p, e := netip.ParsePrefix(cidr)
			if e != nil || p.Addr().Is4() != family.v4 {
				return nil, errNetworkData
			}
			rows = append(rows, identity.NetworkClass{CIDR: cidr, Kind: s.Kind, Label: s.Label, Suffix: s.Suffix, Provider: sourceProvider(s)})
		}
	}
	if _, e := identity.CompileNetworks(rows, networkRowLimit); e != nil {
		return nil, errNetworkData
	}
	return rows, nil
}

// parseNetworkCSV はプロバイダ付き5列または外部回線種別2列のCSVを読む。未知の型は更新を中止する。
func parseNetworkCSV(raw []byte) ([]identity.NetworkClass, error) {
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(raw), "\ufeff")))
	header, e := reader.Read()
	if e != nil {
		return nil, errNetworkData
	}
	own := strings.Join(header, ",") == "cidr,kind,label,suffix,provider"
	connection := strings.Join(header, ",") == "network,connection_type"
	if !own && !connection {
		return nil, errNetworkData
	}
	rows := []identity.NetworkClass{}
	for {
		fields, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errNetworkData
		}
		var r identity.NetworkClass
		if own {
			r = identity.NetworkClass{CIDR: fields[0], Kind: fields[1], Label: fields[2], Suffix: fields[3], Provider: fields[4]}
		} else {
			kind := "unknown"
			switch fields[1] {
			case "Cable/DSL":
				kind = "fixed"
			case "Cellular":
				kind = "mobile"
			case "Corporate", "Satellite":
			default:
				return nil, errNetworkData
			}
			label, suffix := identity.DefaultNetworkDisplay(kind)
			r = identity.NetworkClass{CIDR: fields[0], Kind: kind, Label: label, Suffix: suffix}
		}
		rows = append(rows, r)
		if len(rows) > networkRowLimit {
			return nil, errNetworkData
		}
	}
	if _, e := identity.CompileNetworks(rows, networkRowLimit); e != nil {
		return nil, errNetworkData
	}
	return rows, nil
}

// canonicalNetworkCIDR はHTML入力の単一IP/host bitを正規prefixへ整える。
func canonicalNetworkCIDR(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if ip, e := netip.ParseAddr(raw); e == nil && ip.Zone() == "" {
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()).String(), nil
	}
	p, e := netip.ParsePrefix(raw)
	if e != nil || p.Addr().Is4In6() {
		return "", errNetworkData
	}
	return p.Masked().String(), nil
}

func networkTime(v int64) string {
	if v == 0 {
		return "まだありません"
	}
	return time.Unix(0, v).UTC().Format(time.RFC3339)
}
func networkETag(v uint64) string { return `"network:` + strconv.FormatUint(v, 10) + `"` }

// sourceProvider は未指定ASNに安定した識別キーを与え、表示名変更でBBを変えない。
func sourceProvider(s NetworkSource) string {
	if s.Provider != "" {
		return s.Provider
	}
	return "asn:" + strconv.FormatUint(uint64(s.ASN), 10)
}

// networkBatch は取得元ごとの検査済み結果。全件成功するまで公開表へ混ぜない。
type networkBatch struct {
	rows []identity.NetworkClass
	err  error
}

// fetchNetworkBatches は最大8要求で全取得元を読み、設定順に結果を返す。
// 取得数が増えてもworker・同時接続を増やさず、取消後は新しい取得を開始しない。
func fetchNetworkBatches(ctx context.Context, client *http.Client, sources []NetworkSource) []networkBatch {
	batches, jobs := networkRowJobs(ctx, client, sources)
	errs := runNetworkJobs(ctx, jobs)
	for i, err := range errs {
		batches[i].err = err
	}
	return batches
}

// networkRowJobs は行の合計保持上限を共有し、取得自体はworker間で並行する。
func networkRowJobs(ctx context.Context, client *http.Client, sources []NetworkSource) ([]networkBatch, []func() error) {
	batches := make([]networkBatch, len(sources))
	jobs := make([]func() error, len(sources))
	seen := map[string]identity.NetworkClass{}
	var mutex sync.Mutex
	for i, source := range sources {
		if source.Type == "japan" || source.Type == "vpn" || source.Type == "countries" {
			continue
		}
		jobs[i] = func() error {
			rows, err := fetchNetworkSource(ctx, client, source)
			if err != nil {
				return err
			}
			mutex.Lock()
			defer mutex.Unlock()
			rows, err = retainNetworkBatch(rows, seen)
			if err == nil {
				batches[i].rows = rows
			}
			return err
		}
	}
	return batches, jobs
}

// fetchNetworkSource はHTTPS・本文サイズ・ASN・空集合の検査を一取得元に適用する。
func fetchNetworkSource(ctx context.Context, client *http.Client, source NetworkSource) ([]identity.NetworkClass, error) {
	target := source.URL
	if source.Type == "asn" {
		target = fmt.Sprintf("https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/%d/aggregated.json", source.ASN)
	}
	raw, err := fetchNetworkBody(ctx, client, target)
	if err != nil {
		return nil, err
	}
	var rows []identity.NetworkClass
	if source.Type == "asn" {
		rows, err = parseASNNetworks(raw, source)
	} else {
		rows, err = parseNetworkCSV(raw)
	}
	if err != nil || len(rows) == 0 {
		return nil, errNetworkData
	}
	return rows, nil
}

// retainNetworkBatch は並列結果の重複を除き、保持する全取得元合計を4万prefixに制限する。
// 呼び出し元がmutexを保持する。途中までの結果も全件成功するまでは公開しない。
func retainNetworkBatch(rows []identity.NetworkClass, seen map[string]identity.NetworkClass) ([]identity.NetworkClass, error) {
	retained := []identity.NetworkClass{}
	for _, row := range rows {
		if old, ok := seen[row.CIDR]; ok {
			merged, ok := mergeAutomaticNetwork(old, row)
			if !ok {
				return nil, errNetworkData
			}
			if merged != old {
				seen[row.CIDR] = merged
				retained = append(retained, merged)
			}
			continue
		}
		if len(seen) >= networkRowLimit {
			return nil, errNetworkData
		}
		seen[row.CIDR] = row
		retained = append(retained, row)
	}
	return retained, nil
}

// mergeAutomaticNetwork は検査済みの同一prefixを統合し、食い違う分類を不明として残す。
// 不明化した値は後続の一致行でも復活させず、完了順と設定順による再統合の差を防ぐ。
// 管理者の手動上書きと、独立した国・VPNの判定には適用しない。
func mergeAutomaticNetwork(a, b identity.NetworkClass) (identity.NetworkClass, bool) {
	if a.CIDR != b.CIDR {
		return identity.NetworkClass{}, false
	}
	if a == b {
		return a, true
	}
	if a.Kind != b.Kind || a.Label != b.Label || a.Suffix != b.Suffix {
		label, suffix := identity.DefaultNetworkDisplay("unknown")
		return identity.NetworkClass{CIDR: a.CIDR, Kind: "unknown", Label: label, Suffix: suffix}, true
	}
	a.Provider = ""
	return a, true
}
