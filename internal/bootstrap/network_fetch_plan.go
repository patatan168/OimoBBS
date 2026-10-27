// ASN・国・VPNを共通の有界worker群で取得し、全件成功後だけ候補を組み立てる。
package bootstrap

import (
	"context"
	"net/http"
	"oimobbs/internal/identity"
	"sync"
	"sync/atomic"
)

// runNetworkJobs は種類を問わず最大8処理を並行し、取消後の新規取得を止める。
func runNetworkJobs(ctx context.Context, jobs []func() error) []error {
	return runNetworkJobsLimit(ctx, jobs, 8)
}

// runNetworkJobsLimit はCPU解析にも同じ取消・完了待ちの規則を使う。
func runNetworkJobsLimit(ctx context.Context, jobs []func() error, limit int) []error {
	errs := make([]error, len(jobs))
	var next atomic.Uint64
	var workers sync.WaitGroup
	for range min(limit, len(jobs)) {
		workers.Go(func() {
			for {
				i := int(next.Add(1) - 1)
				if i >= len(jobs) {
					return
				}
				if jobs[i] == nil {
					continue
				}
				if err := ctx.Err(); err != nil {
					errs[i] = err
					continue
				}
				errs[i] = jobs[i]()
			}
		})
	}
	workers.Wait()
	return errs
}

type networkAccessPlan struct {
	jobs    []func() error
	results []*networkAccessData
}

// newNetworkAccessPlan はVPNをfamily別にし、重複設定でも同じ結果へ同時書込みしない。
func newNetworkAccessPlan(ctx context.Context, client *http.Client, sources []NetworkSource) *networkAccessPlan {
	p := &networkAccessPlan{}
	for _, s := range sources {
		if s.Type != "countries" && s.Type != "japan" && s.Type != "vpn" {
			continue
		}
		out := &networkAccessData{}
		p.results = append(p.results, out)
		switch s.Type {
		case "countries":
			p.jobs = append(p.jobs, func() error { var err error; out.Countries, err = fetchCountries(ctx, client); return err })
		case "japan":
			p.jobs = append(p.jobs, func() error { var err error; out.Japan, err = fetchJapanPrefixes(ctx, client); return err })
		case "vpn":
			p.jobs = append(p.jobs, func() error { var err error; out.VPN4, err = fetchVPNPrefixes(ctx, client, true); return err }, func() error { var err error; out.VPN6, err = fetchVPNPrefixes(ctx, client, false); return err })
		}
	}
	return p
}

// finish は全workerの終了後に設定順で統合し、未取得と空集合を区別して検証する。
func (p *networkAccessPlan) finish() (*networkAccessData, error) {
	var out *networkAccessData
	for _, part := range p.results {
		if out == nil {
			out = &networkAccessData{}
		}
		if part.Countries != "" {
			out.Countries = part.Countries
		}
		if part.Japan != nil {
			out.Japan = part.Japan
		}
		if part.VPN4 != nil {
			out.VPN4 = part.VPN4
			out.VPN6 = part.VPN6
		}
	}
	if _, err := compileAccessData(out, nil); err != nil {
		return nil, err
	}
	return out, nil
}

// fetchNetworkUpdate は大きい登録国表を先に投入し、ASN取得中もCPUで解析を進める。
// 取得元数やコア数にかかわらず同時取得を8以下に保ち、一部成功を公開しない。
func fetchNetworkUpdate(ctx context.Context, client *http.Client, sources []NetworkSource) ([]identity.NetworkClass, *networkAccessData, error) {
	if len(sources) > networkSourceLimit {
		return nil, nil, errNetworkData
	}
	access := newNetworkAccessPlan(ctx, client, sources)
	batches, rowJobs := networkRowJobs(ctx, client, sources)
	errs := runNetworkJobs(ctx, append(access.jobs, rowJobs...))
	for i, err := range errs[len(access.jobs):] {
		batches[i].err = err
	}
	rows, err := mergeNetworkBatches(batches, sources)
	if err != nil {
		return nil, nil, err
	}
	for _, err := range errs[:len(access.jobs)] {
		if err != nil {
			return nil, nil, err
		}
	}
	data, err := access.finish()
	return rows, data, err
}
