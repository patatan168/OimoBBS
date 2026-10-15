// 永続欠測集計の作成intent、共通容量予約、snapshotと管理状態を製品へ接続する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const optionalLossDir = "http-loss"

// ErrOptionalLossPersistence は終了時に欠測snapshotを同期できなかった状態。
var ErrOptionalLossPersistence = errors.New("optional HTTP loss snapshot not durable")

// validateOptionalLossActivation は専用schemaと同一siteのpreparing→activeだけを許可する。
func validateOptionalLossActivation(key string, old, next json.RawMessage) error {
	var v optionalLogActivation
	if key != "http" || strictjson.Decode(next, &v) != nil || v.Schema != "optional-http-loss-activation-v1" {
		return store.ErrCorrupt
	}
	// 遷移はHTTP本体と共通だが、異なるschemaの混入を許さない。
	v.Schema = "optional-http-activation-v1"
	raw, _ := json.Marshal(v)
	var prior json.RawMessage
	if len(old) > 0 {
		var p optionalLogActivation
		if strictjson.Decode(old, &p) != nil || p.Schema != "optional-http-loss-activation-v1" {
			return store.ErrCorrupt
		}
		p.Schema = v.Schema
		prior, _ = json.Marshal(p)
	}
	return validateOptionalLogActivation(key, prior, raw)
}

// inspectOptionalLossLogs は読取り検査と、作成/候補補完を許す起動を区別する。
func inspectOptionalLossLogs(cfg Config, site siteState, state store.ControlState, allowPending bool, key ed25519.PrivateKey) error {
	root := filepath.Join(cfg.DataDir, "reports", optionalLossDir)
	row, ok := state.Rows["optional_loss:http"]
	if !ok {
		if _, e := os.Lstat(root); !os.IsNotExist(e) {
			if e != nil {
				return e
			}
			return store.ErrCorrupt
		}
		return nil
	}
	var a optionalLogActivation
	if strictjson.Decode(row.Value, &a) != nil || a.Site != site.ID || site.MinimumReader < 40 {
		return store.ErrCorrupt
	}
	if a.Phase == "preparing" && !allowPending {
		return store.ErrIncomplete
	}
	if _, e := os.Lstat(root); os.IsNotExist(e) && a.Phase == "preparing" {
		return nil
	} else if e != nil {
		return e
	}
	if !allowPending {
		if e := evidence.InspectOptionalLoss(root, site.ID, key.Public().(ed25519.PublicKey)); e != nil {
			return e
		}
		if a.Phase == "active" {
			if _, e := os.Lstat(filepath.Join(root, evidence.OptionalLossFile)); e != nil {
				return store.ErrCorrupt
			}
		}
		return nil
	}
	s, e := evidence.OpenOptionalLoss(root, site.ID, key)
	if e != nil {
		return e
	}
	defer s.Close()
	if _, exists := s.Summary(); !exists && a.Phase == "active" {
		return store.ErrCorrupt
	}
	return nil
}

// prepareOptionalLoss はsite所有mutex内でreader40と作成intentを先に同期する。
func (r *Repository) prepareOptionalLoss(site siteState, key ed25519.PrivateKey) error {
	row, exists := r.site.State().Rows["optional_loss:http"]
	a := optionalLogActivation{Schema: "optional-http-loss-activation-v1", Site: site.ID, Phase: "preparing"}
	if exists {
		if e := strictjson.Decode(row.Value, &a); e != nil {
			return e
		}
	} else {
		site.MinimumReader = max(site.MinimumReader, 40)
		if e := appendControl(r.site, "optional_loss_prepare", []store.Mutation{mutation("site", "state", site, nil), mutation("optional_loss", "http", a, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
	}
	root := filepath.Join(r.cfg.DataDir, "reports", optionalLossDir)
	if a.Phase == "preparing" {
		if e := os.Mkdir(root, 0700); e != nil && !os.IsExist(e) {
			return e
		}
		if e := privatePath(root, true); e != nil {
			return e
		}
		if e := store.SyncDirectory(filepath.Dir(root)); e != nil {
			return e
		}
	}
	s, e := evidence.OpenOptionalLoss(root, site.ID, key)
	if e != nil {
		return e
	}
	r.optionalLoss = s
	r.optionalLossSite = site.ID
	r.optionalLossStarted = time.Now()
	return nil
}

// snapshotOptionalLossLocked は確定したcounterだけを16KiB枠で同期する。r.muを保持する。
// 容量/保存失敗は管理状態へ残し、非必須ログや必須投稿のworkerを停止しない。
func (r *Repository) snapshotOptionalLossLocked(clean bool) {
	r.optionalLossMu.Lock()
	err := r.writeOptionalLossLocked(clean)
	r.optionalLossFailed = err != nil
	r.optionalLossMu.Unlock()
	if err == nil {
		r.activateOptionalLossLocked()
	}
}

// writeOptionalLossLocked は欠測専用mutexを保持して呼ぶ。周期Sync中はsite mutexを使わない。
func (r *Repository) writeOptionalLossLocked(clean bool) error {
	release, e := r.reservePrivateLossBytes(16 << 10)
	if e != nil {
		return e
	}
	defer release()
	root := filepath.Join(r.cfg.DataDir, "reports", optionalLossDir)
	if r.optionalLossBeforeSnapshot != nil {
		r.optionalLossBeforeSnapshot()
	}
	if r.optionalLoss == nil || r.optionalLoss.Stopped() {
		if r.optionalLoss != nil {
			r.optionalLoss.Close()
		}
		seed, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "evidence-000010.seed"), 32)
		if e != nil {
			return e
		}
		defer clear(seed)
		if len(seed) != ed25519.SeedSize {
			return store.ErrCorrupt
		}
		key := ed25519.NewKeyFromSeed(seed)
		defer clear(key)
		s, e := evidence.OpenOptionalLoss(root, r.optionalLossSite, key)
		if e != nil {
			return e
		}
		r.optionalLoss = s
		if r.optionalLossBoot != (domain.ID{}) {
			if e = s.Resume(r.optionalLossBoot); e != nil {
				return e
			}
		}
	}
	if r.optionalLossBoot == (domain.ID{}) {
		v, e := r.optionalLoss.Begin(r.optionalLossStarted, r.optionalStore.StartupDiscarded())
		if v.Boot != (domain.ID{}) && (e == nil || r.optionalLoss.Stopped()) {
			r.optionalLossBoot = v.Boot
		}
		if e != nil {
			return e
		}
	}
	if r.optionalQueue != nil {
		if _, e := r.optionalLoss.Capture(r.optionalQueue.Status(), time.Now(), clean); e != nil {
			return e
		}
	}
	return nil
}

// activateOptionalLossLocked は初回snapshot完成後だけsite intentを確定する。r.muを保持する。
func (r *Repository) activateOptionalLossLocked() {
	row := r.site.State().Rows["optional_loss:http"]
	var a optionalLogActivation
	if e := strictjson.Decode(row.Value, &a); e != nil {
		r.optionalLossMu.Lock()
		r.optionalLossFailed = true
		r.optionalLossMu.Unlock()
		return
	}
	if a.Phase == "preparing" {
		a.Phase = "active"
		if e := appendControl(r.site, "optional_loss_activate", []store.Mutation{mutation("optional_loss", "http", a, nil)}, []string{}); e != nil {
			r.stopped = true
			r.optionalLossMu.Lock()
			r.optionalLossFailed = true
			r.optionalLossMu.Unlock()
			return
		}
	}
	return
}

// snapshotOptionalLoss は周期処理用。Closeが待つ間はr.muを解放して停止できるようにする。
func (r *Repository) snapshotOptionalLoss() {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return
	}
	// 周期のSyncは必須投稿のsite排他を保持しない。Closeはdoneを待ってからこのownerを閉じる。
	r.optionalLossMu.Lock()
	err := r.writeOptionalLossLocked(false)
	r.optionalLossFailed = err != nil
	r.optionalLossMu.Unlock()
	if err == nil {
		r.mu.Lock()
		if !r.closed {
			r.activateOptionalLossLocked()
		}
		r.mu.Unlock()
	}
}

// OptionalLossStatus は最後の同期snapshotと現在の保存失敗を区別する。個人情報を含まない。
type OptionalLossStatus struct {
	PersistFailed bool                          `json:"persist_failed"`
	HasSnapshot   bool                          `json:"has_snapshot"`
	Summary       *evidence.OptionalLossSummary `json:"summary"`
	Known         evidence.OptionalLossCounts   `json:"known_losses"`
	ObservedTime  string                        `json:"-"`
	KnownRange    string                        `json:"-"`
	UnknownRange  string                        `json:"-"`
}

// optionalLossStatusLocked はsite mutex保持中に最後の同期済み集計を独立値へ複製する。
func (r *Repository) optionalLossStatusLocked() OptionalLossStatus {
	r.optionalLossMu.Lock()
	defer r.optionalLossMu.Unlock()
	out := OptionalLossStatus{PersistFailed: r.optionalLossFailed}
	if r.optionalLoss != nil {
		summary, exists := r.optionalLoss.Summary()
		out.HasSnapshot = exists
		if out.HasSnapshot {
			out.Summary = &summary
			out.ObservedTime = formatOptionalLossInstant(summary.Observed)
			if summary.KnownLossFrom > 0 {
				out.KnownRange = formatOptionalLossInstant(summary.KnownLossFrom) + " ～ " + formatOptionalLossInstant(summary.KnownLossUntil)
			}
			if summary.UnknownFrom > 0 {
				out.UnknownRange = formatOptionalLossInstant(summary.UnknownFrom) + " ～ " + formatOptionalLossInstant(summary.UnknownUntil)
			}
			known, e := summary.Known()
			if e != nil {
				out.PersistFailed = true
			} else {
				out.Known = known
			}
		}
	}
	return out
}

// formatOptionalLossInstant は署名集計の観測時刻をUTC/JST両方で表示する。
func formatOptionalLossInstant(at domain.Time) string {
	if at <= 0 {
		return ""
	}
	instant := time.Unix(0, int64(at))
	return instant.UTC().Format(time.RFC3339Nano) + " / " + instant.In(domain.JST).Format(time.RFC3339Nano)
}
