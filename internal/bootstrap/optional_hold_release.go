// 元解除参照の案件保存に先立ち最低reader43を同期し、現在元正本との全一致を維持する。
package bootstrap

import (
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// enableOptionalReleaseReaderLocked は元解除台帳保存前にsite最低readerを単調に進める。r.muを保持する。
func (r *Repository) enableOptionalReleaseReaderLocked() error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader >= 43 {
		return nil
	}
	site.MinimumReader = 43
	if e := appendControl(r.site, "optional_http_release_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}

// recordTerminalOptionalRelease は照合済み元解除の署名参照を保存する。コピー/期限は変えない。
func (r *Repository) recordTerminalOptionalRelease(c disclosure.Case, receipt evidence.OptionalHoldReceipt) (disclosure.Case, error) {
	if c.HTTP.Released != nil {
		return r.evidenceCases.RecordHTTPRelease(c.ID, c.Creator, c.ETag(), receipt, time.Now())
	}
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return c, e
	}
	defer release()
	if e = r.enableOptionalReleaseReaderLocked(); e != nil {
		return c, e
	}
	return r.evidenceCases.RecordHTTPRelease(c.ID, c.Creator, c.ETag(), receipt, time.Now())
}

// confirmTerminalOptionalRelease は元CAS解除後に現在解除正本を再照合し、案件排他を取り直して保存する。
func (r *Repository) confirmTerminalOptionalRelease(c disclosure.Case, source *evidence.OptionalStore) (disclosure.Case, error) {
	var receipt evidence.OptionalHoldReceipt
	e := r.awaitOptionalHoldOwner(func() error {
		var e error
		receipt, e = source.CheckOptionalHoldReceipt(*c.HTTP.Reservation)
		if e != nil {
			return e
		}
		if receipt.State != "released" {
			return store.ErrIncomplete
		}
		return nil
	})
	if e != nil {
		return c, e
	}
	if e = r.recheckTerminalOptionalHold(c, source); e != nil {
		return c, e
	}
	return r.recordTerminalOptionalRelease(c, receipt)
}
