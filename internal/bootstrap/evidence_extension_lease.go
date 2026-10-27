// 署名済み延長intentの元lease更新/案件確定を、元待ち中の案件排他解放で進める。
package bootstrap

import (
	"context"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// enableOptionalExtensionReaderLocked は延長intentより先にsite最低reader44をSyncする。
func (r *Repository) enableOptionalExtensionReaderLocked() error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader >= 44 {
		return nil
	}
	site.MinimumReader = 44
	if e := appendControl(r.site, "optional_http_extension_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}

// extensionSourceReceipt は同じ所有者の最新元参照と既存案件参照の前hashを案件mutex外で照合する。
func (r *Repository) extensionSourceReceipt(ctx context.Context, c disclosure.Case, source *evidence.OptionalStore) (evidence.OptionalHoldReceipt, bool, error) {
	var receipt evidence.OptionalHoldReceipt
	var found bool
	e := r.awaitOptionalHoldOwner(func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := source.ReloadOptionalHolds(); e != nil {
			return e
		}
		var e error
		receipt, found, e = source.OptionalHoldReceipt(c.ID)
		if e != nil || !found {
			return e
		}
		if c.HTTP.Reservation != nil {
			current, err := source.CheckOptionalHoldReceipt(*c.HTTP.Reservation)
			if err != nil {
				return err
			}
			receipt = current
		}
		return nil
	})
	return receipt, found, e
}

// renewPendingExtension はlifecycle/案件排他下で入り、元正本/前hashを照合してから期限を確定する。
// recheckは元待ち後の現在認可。起動/周期は既に署名されたintentのmetadataだけを再開する。
func (r *Repository) renewPendingExtension(ctx context.Context, c disclosure.Case, source *evidence.OptionalStore, recheck func() error) (disclosure.Case, error) {
	if source == nil || c.Extension == nil || c.Extension.State != "pending" {
		return c, store.ErrIncomplete
	}
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return c, e
	}
	defer release()
	x := c.Extension
	b := x.Original.Binding
	b.Revision = x.Revision
	b.Until = x.Until
	var receipt evidence.OptionalHoldReceipt
	afterRenew := r.optionalExtensionAfterRenew
	e = r.awaitOptionalHoldOwner(func() error {
		if e := source.ReloadOptionalHolds(); e != nil {
			return e
		}
		if e := source.ProtectOptionalHoldRenewal(x.Original, b, x.Requested); e != nil {
			return e
		}
		var e error
		receipt, e = source.RenewOptionalHold(ctx, x.Original, b, x.Requested, time.Now())
		if e != nil {
			return e
		}
		if afterRenew != nil {
			afterRenew()
		}
		current, e := source.CheckOptionalHoldReceipt(x.Original)
		if e != nil {
			return e
		}
		if current.SHA != receipt.SHA || current.Sequence != receipt.Sequence {
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
	if e = ctx.Err(); e != nil {
		return c, e
	}
	if recheck != nil {
		if e = recheck(); e != nil {
			return c, e
		}
	}
	// lifecycleと案件排他を保持し、pending中のHTTP元更新は同じ排他で停止している。
	return r.evidenceCases.CompleteExtension(c.ID, x.Actor, c.ETag(), receipt, time.Now(), func() error { return nil })
}
