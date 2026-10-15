// 必須元予約の板別有効化intentと私有領域を、最低reader46の先行Syncへ束縛する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strings"
)

const requiredHoldStorageDirectory = "required-original-holds"
const requiredHoldActivationSchema = "required-original-holds-activation-v1"

type requiredHoldActivation struct {
	Schema string    `json:"schema"`
	Site   domain.ID `json:"site_id"`
	Board  domain.ID `json:"board_id"`
	Phase  string    `json:"phase"`
}

func requiredHoldStoragePath(root string, board domain.ID) string {
	return filepath.Join(root, "reports", requiredHoldStorageDirectory, board.String())
}

// decodeRequiredHoldActivation は有効化行の完全型と正規板IDを検査する。
func decodeRequiredHoldActivation(key string, raw json.RawMessage) (requiredHoldActivation, error) {
	var a requiredHoldActivation
	if strictjson.Decode(raw, &a) != nil {
		return a, store.ErrCorrupt
	}
	if !validRequiredHoldActivation(key, a) {
		return a, store.ErrCorrupt
	}
	return a, nil
}

// validRequiredHoldActivation は所有者の混同と未知phaseを拒否する。
func validRequiredHoldActivation(key string, a requiredHoldActivation) bool {
	return a.Schema == requiredHoldActivationSchema && a.Site != (domain.ID{}) && a.Board != (domain.ID{}) && a.Site != a.Board && key == a.Board.String() && (a.Phase == "preparing" || a.Phase == "active")
}

// validateRequiredHoldActivation は板別intentの準備→有効化だけを許し、欠落を復旧で埋めない。
func validateRequiredHoldActivation(key string, old, next json.RawMessage) error {
	a, e := decodeRequiredHoldActivation(key, next)
	if e != nil {
		return e
	}
	if len(old) == 0 {
		if a.Phase != "preparing" {
			return store.ErrCorrupt
		}
		return nil
	}
	prior, e := decodeRequiredHoldActivation(key, old)
	if e != nil {
		return e
	}
	if prior.Site != a.Site || prior.Board != a.Board || prior.Phase != "preparing" || a.Phase != "active" {
		return store.ErrCorrupt
	}
	return nil
}

// requiredHoldActivations は既知の有効板/最低readerへ全intentを束縛する。期限付き行を許可しない。
func requiredHoldActivations(state store.ControlState, site siteState) (map[domain.ID]requiredHoldActivation, error) {
	result := map[domain.ID]requiredHoldActivation{}
	dirs, e := siteDirectories(state)
	if e != nil {
		return nil, e
	}
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "required_holds:") {
			continue
		}
		a, e := decodeRequiredHoldActivation(strings.TrimPrefix(name, "required_holds:"), row.Value)
		if e != nil {
			return nil, e
		}
		if row.Expires != nil || !requiredHoldActivationMatchesSite(a, site, dirs) {
			return nil, store.ErrCorrupt
		}
		result[a.Board] = a
	}
	return result, nil
}

// requiredHoldActivationMatchesSite は現在の有効板集合とreader46に元intentを束縛する。
func requiredHoldActivationMatchesSite(a requiredHoldActivation, site siteState, dirs map[domain.ID]*boardDirectory) bool {
	return a.Site == site.ID && site.MinimumReader >= 46 && dirs[a.Board] != nil && dirs[a.Board].Status == "active"
}

// requiredHoldReportEntries は承認済みintentがある領域名だけをreportsの既知集合へ渡す。
// 詳細/全元署名はinspectRequiredHoldStorageで、原本復旧より先に検査する。
func requiredHoldReportEntries(root string, state store.ControlState) ([]string, error) {
	registered := false
	for name := range state.Rows {
		registered = registered || strings.HasPrefix(name, "required_holds:")
	}
	extra := []string{}
	if _, enabled := state.Rows["report_store:active"]; enabled {
		if _, e := os.Lstat(filepath.Join(root, "reports", reportDirectory)); e == nil {
			extra = append(extra, reportDirectory)
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	if !registered {
		return extra, nil
	}
	if _, e := os.Lstat(filepath.Join(root, "reports", requiredHoldStorageDirectory)); os.IsNotExist(e) {
		return extra, nil
	} else if e != nil {
		return nil, e
	}
	return append(extra, requiredHoldStorageDirectory), nil
}

// prepareRequiredHoldParent は先行site intent確定後にだけ板別台帳の親領域を同期する。
func prepareRequiredHoldParent(root string) error {
	path := filepath.Join(root, "reports", requiredHoldStorageDirectory)
	if e := os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	if e := privatePath(path, true); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(path))
}

// initializeRequiredHoldStorage は同じ板所有列で空集合をSyncする。有効台帳の欠落は補完しない。
func (b *postingBoard) initializeRequiredHoldStorage(required bool) error {
	if b.requiredHolds != nil {
		_, e := b.requiredHolds.Held(domain.ID{}, domain.Time(b.clock().UnixNano()))
		return e
	}
	if !required {
		if e := prepareRequiredHoldParent(b.root); e != nil {
			return e
		}
	}
	h, e := app.OpenRequiredOriginalHolds(requiredHoldStoragePath(b.root, b.owner), b.owner, 10, b.key, required)
	if e != nil {
		return e
	}
	if !required {
		e = b.initializeEmptyRequiredHoldStorage(h)
	}

	if e == nil {
		_, e = h.Held(domain.ID{}, domain.Time(b.clock().UnixNano()))
	}
	if e != nil {
		return errors.Join(e, h.Close())
	}
	b.requiredHolds = h
	return nil
}

// initializeEmptyRequiredHoldStorage は準備中の空集合だけを確定し、未有効化の予約行を拒否する。
func (b *postingBoard) initializeEmptyRequiredHoldStorage(h *app.RequiredOriginalHolds) error {
	if e := h.Initialize(domain.Time(b.clock().UnixNano())); e != nil {
		return e
	}
	inspection, e := app.InspectRequiredOriginalHolds(requiredHoldStoragePath(b.root, b.owner), b.owner, 10, b.key)
	if e != nil {
		return e
	}
	if len(inspection.Receipts) != 0 {
		return store.ErrCorrupt
	}
	return nil
}

// activateRequiredHoldStorage は元空集合の同期確認後、site所有排他で有効化を確定する。
func (r *Repository) activateRequiredHoldStorage(board domain.ID) error {
	name := "required_holds:" + board.String()
	row, ok := r.site.State().Rows[name]
	if !ok {
		return store.ErrCorrupt
	}
	a, e := decodeRequiredHoldActivation(board.String(), row.Value)
	if e != nil {
		return e
	}
	if a.Phase == "active" {
		return nil
	}
	a.Phase = "active"
	if e = appendControl(r.site, "required_holds_active", []store.Mutation{mutation("required_holds", board.String(), a, nil)}, []string{}); e != nil {
		r.stopped = true
	}
	return e
}

// ensureRequiredHoldStorage は現在認可を呼出元で検査した後、reader/intentを先行Syncする。
// 元所有列待ちで案件mutexを解放し、取り直した現在site/板の後にactiveを確定する。
func (r *Repository) ensureRequiredHoldStorage(ctx context.Context, owner domain.ID) error {
	release, e := r.reservePrivateLogBytes(256 << 10)
	if e != nil {
		return e
	}
	defer release()
	r.mu.Lock()
	b, a, e := r.prepareRequiredHoldStorageLocked(ctx, owner)
	r.mu.Unlock()
	if e != nil {
		return e
	}
	_, e = b.worker.Submit(ctx, func() (any, error) { return nil, b.initializeRequiredHoldStorage(a.Phase == "active") })
	if e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.available(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if r.posting[owner] != b {
		return store.ErrIncomplete
	}
	return r.activateRequiredHoldStorage(owner)
}

// prepareRequiredHoldStorageLocked はサイト排他下で板の現存/readerと未作成intentを同期する。
func (r *Repository) prepareRequiredHoldStorageLocked(ctx context.Context, owner domain.ID) (*postingBoard, requiredHoldActivation, error) {
	var a requiredHoldActivation
	if e := r.available(); e != nil {
		return nil, a, e
	}
	if e := ctx.Err(); e != nil {
		return nil, a, e
	}
	b := r.posting[owner]
	if b == nil || b.worker == nil {
		return nil, a, ErrPostingUnavailable
	}
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return nil, a, e
	}
	if row, ok := r.site.State().Rows["required_holds:"+owner.String()]; ok {
		a, e := decodeRequiredHoldActivation(owner.String(), row.Value)
		return b, a, e
	}
	a = requiredHoldActivation{Schema: requiredHoldActivationSchema, Site: site.ID, Board: owner, Phase: "preparing"}
	site.MinimumReader = max(site.MinimumReader, 46)
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("required_holds", owner.String(), a, nil)}
	if e := appendControl(r.site, "required_holds_prepare", changes, []string{}); e != nil {
		r.stopped = true
		return nil, a, e
	}
	return b, a, nil
}

// openRequiredHoldStorage は起動の横断検査後、元Journal復旧の前に板所有台帳を開く。
func (r *Repository) openRequiredHoldStorage(b *postingBoard) error {
	if r.requiredHoldsOmitted {
		return nil
	}
	row, ok := r.site.State().Rows["required_holds:"+b.owner.String()]
	if !ok {
		return nil
	}
	a, e := decodeRequiredHoldActivation(b.owner.String(), row.Value)
	if e != nil {
		return e
	}
	if e = b.initializeRequiredHoldStorage(a.Phase == "active"); e != nil {
		return e
	}
	return r.activateRequiredHoldStorage(b.owner)
}

// requireReportEntries は空集合もEOFを欠落扱いせず、既知領域の完全一致を検査する。
func requireReportEntries(path string, names []string) error {
	if len(names) == 0 {
		return requireEmpty(path)
	}
	return requireEntries(path, names)
}
