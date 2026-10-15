// 元HTTP予約領域の先行site intent・有効化・起動時の必須存在検査を製品へ接続する。
package bootstrap

import (
	"context"
	"encoding/json"
	"path/filepath"

	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const optionalHoldActivationSchema = "optional-http-holds-activation-v1"

// validateOptionalHoldActivation は別schemaを固定し、preparing→activeの一方向だけを許可する。
func validateOptionalHoldActivation(key string, old, next json.RawMessage) error {
	var v optionalLogActivation
	if strictjson.Decode(next, &v) != nil || v.Schema != optionalHoldActivationSchema {
		return store.ErrCorrupt
	}
	v.Schema = "optional-http-activation-v1"
	raw, _ := json.Marshal(v)
	var prior json.RawMessage
	if len(old) > 0 {
		var p optionalLogActivation
		if strictjson.Decode(old, &p) != nil || p.Schema != optionalHoldActivationSchema {
			return store.ErrCorrupt
		}
		p.Schema = v.Schema
		prior, _ = json.Marshal(p)
	}
	return validateOptionalLogActivation(key, prior, raw)
}

// inspectOptionalHoldActivation はactiveの領域/確定索引欠落を原本GCの起動前に拒否する。
// preparingだけが初回作成を補完でき、読取りcheckはその状態を変更しない。
func inspectOptionalHoldActivation(cfg Config, site siteState, state store.ControlState, allowPending bool) error {
	row, exists := state.Rows["optional_holds:http"]
	if !exists {
		return nil
	}
	var a optionalLogActivation
	if strictjson.Decode(row.Value, &a) != nil || a.Schema != optionalHoldActivationSchema || a.Site != site.ID || site.MinimumReader < 42 {
		return store.ErrCorrupt
	}
	if a.Phase == "preparing" {
		if !allowPending {
			return store.ErrIncomplete
		}
		return nil
	}
	if a.Phase != "active" {
		return store.ErrCorrupt
	}
	root := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory)
	if e := privatePath(root, true); e != nil {
		return store.ErrCorrupt
	}
	if e := privatePath(filepath.Join(root, evidence.OptionalHoldIndexFile), false); e != nil {
		return store.ErrCorrupt
	}
	return nil
}

// ensureOptionalHoldStorage は認可済みHTTP保全の前にsite intentを同期し、案件mutexを解放して初期化する。
// 原本予約・コピーはこの処理のactive確定後に開始する。
func (r *Repository) ensureOptionalHoldStorage(ctx context.Context) error {
	release, e := r.reservePrivateLogBytes(256 << 10)
	if e != nil {
		return e
	}
	defer release()
	r.mu.Lock()
	if e = r.available(); e == nil {
		e = ctx.Err()
	}
	if e != nil {
		r.mu.Unlock()
		return e
	}
	source := r.optionalStore
	if source == nil {
		r.mu.Unlock()
		return &adminFailure{status: 409, code: "OPTIONAL_HTTP_NOT_ENABLED"}
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		r.mu.Unlock()
		return e
	}
	a := optionalLogActivation{Schema: optionalHoldActivationSchema, Site: site.ID, Phase: "preparing"}
	if row, exists := r.site.State().Rows["optional_holds:http"]; exists {
		if e = strictjson.Decode(row.Value, &a); e != nil {
			r.mu.Unlock()
			return e
		}
	} else {
		if site.MinimumReader < 42 {
			r.mu.Unlock()
			return store.ErrCorrupt
		}
		if e = appendControl(r.site, "optional_holds_prepare", []store.Mutation{mutation("optional_holds", "http", a, nil)}, []string{}); e != nil {
			r.stopped = true
			r.mu.Unlock()
			return e
		}
	}
	beforeInitialize := r.optionalHoldBeforeInitialize
	r.mu.Unlock()
	if a.Phase == "preparing" {
		if beforeInitialize != nil {
			beforeInitialize()
		}
		if e = source.ReloadOptionalHolds(); e != nil {
			return e
		}
		if e = source.InitializeOptionalHolds(); e != nil {
			return e
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.available(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if r.optionalStore != source {
		return store.ErrIncomplete
	}
	return r.activateOptionalHolds()
}

// activateOptionalHolds は初期化済み索引の後に、site所有mutex内または単独起動で有効化を確定する。
func (r *Repository) activateOptionalHolds() error {
	var a optionalLogActivation
	if e := strictjson.Decode(r.site.State().Rows["optional_holds:http"].Value, &a); e != nil {
		return e
	}
	if a.Phase == "active" {
		return nil
	}
	if a.Phase != "preparing" {
		return store.ErrCorrupt
	}
	a.Phase = "active"
	if e := appendControl(r.site, "optional_holds_activate", []store.Mutation{mutation("optional_holds", "http", a, nil)}, []string{}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}

// resumeOptionalHoldStorage は単独起動で既知preparingだけを補完し、未導入領域を自動作成しない。
func (r *Repository) resumeOptionalHoldStorage(source *evidence.OptionalStore) error {
	row, exists := r.site.State().Rows["optional_holds:http"]
	if !exists {
		return nil
	}
	var a optionalLogActivation
	if e := strictjson.Decode(row.Value, &a); e != nil {
		return e
	}
	if a.Phase == "active" {
		return nil
	}
	release, e := r.reservePrivateLogBytes(256 << 10)
	if e != nil {
		return e
	}
	defer release()
	if e := source.InitializeOptionalHolds(); e != nil {
		return e
	}
	return r.activateOptionalHolds()
}
