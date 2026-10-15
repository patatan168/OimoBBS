// 独立した排他所有プロセスで、再生作業領域の有界巡回を周期実行する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
)

// ReplayMaintenanceOptions は一つのbundleに対応する専用作業親と巡回上限。
type ReplayMaintenanceOptions struct {
	WorkParent string
	Keys       string
	Limit      int
	Interval   time.Duration
	Budget     time.Duration
	Apply      bool
}

// ReplayMaintenanceReport は一回の巡回結果。詳細エラーや鍵を含めない。
type ReplayMaintenanceReport struct {
	Pass   domain.U64        `json:"pass"`
	Status string            `json:"status"`
	Apply  bool              `json:"apply"`
	Sweep  ReplaySweepReport `json:"sweep"`
}

func (o ReplayMaintenanceOptions) validate() error {
	if o.Limit < 1 || o.Limit > 128 || o.Interval < time.Minute || o.Interval > 24*time.Hour || o.Budget < time.Second || o.Budget > 5*time.Minute {
		return errors.New("replay maintenance requires limit 1..128, interval 1m..24h and budget 1s..5m")
	}
	return separateBackupPaths(o.WorkParent, o.Keys)
}

// RunBackupReplayMaintenance は即時に一回巡回し、完了後interval待って次ページを処理する。
// 親の.lockを終了まで保持し、同じ親の二重定期実行を拒否する。取消・出力失敗時は終了する。
// emitは逐次呼び出す。遅い出力先の書込みをcontextで強制中断する契約ではない。
func RunBackupReplayMaintenance(ctx context.Context, o ReplayMaintenanceOptions, emit func(ReplayMaintenanceReport) error) error {
	return runBackupReplayMaintenance(ctx, o, emit, waitReplayMaintenance, SweepBackupReplay)
}

// RunIndependentReplayMaintenance はo.Keysの独立回収鍵だけで停止領域を定期回収する。
// バックアップ鍵束を開かず、親inodeと独立鍵の変更時には停止する。
func RunIndependentReplayMaintenance(ctx context.Context, o ReplayMaintenanceOptions, emit func(ReplayMaintenanceReport) error) error {
	return runReplayMaintenanceMode(ctx, o, emit, waitReplayMaintenance, SweepBackupReplayWithCleanupKey, true)
}

// runBackupReplayMaintenance は待機と巡回を注入可能にし、試験で実時間の待機を避ける。
func runBackupReplayMaintenance(ctx context.Context, o ReplayMaintenanceOptions, emit func(ReplayMaintenanceReport) error, wait func(context.Context, time.Duration) error, sweep func(context.Context, string, string, string, int, bool) (ReplaySweepReport, error)) (err error) {
	return runReplayMaintenanceMode(ctx, o, emit, wait, sweep, false)
}

// runReplayMaintenanceMode は共通の排他・周期・中断処理と用途別の鍵検証を接続する。
func runReplayMaintenanceMode(ctx context.Context, o ReplayMaintenanceOptions, emit func(ReplayMaintenanceReport) error, wait func(context.Context, time.Duration) error, sweep func(context.Context, string, string, string, int, bool) (ReplaySweepReport, error), independent bool) (err error) {
	if err = o.validate(); err != nil {
		return err
	}
	if emit == nil {
		return errors.New("replay maintenance requires a report writer")
	}
	if err = privatePath(o.WorkParent, true); err != nil {
		return err
	}
	identity, err := captureReplayMaintenanceIdentityMode(o, independent)
	if err != nil {
		return err
	}
	if independent {
		key, e := independentReplayKey(o.Keys)
		clear(key[:])
		err = e
	} else {
		_, err = loadBackupKeys(ctx, o.Keys)
	}
	if err != nil {
		return err
	}
	lock, err := platform.Lock(o.WorkParent)
	if err != nil {
		return err
	}
	defer func() {
		if e := platform.Unlock(lock); e != nil {
			err = errors.Join(err, e)
		}
	}()
	after := ""
	for pass := domain.U64(1); ; pass++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		next, e := captureReplayMaintenanceIdentityMode(o, independent)
		if e != nil {
			return e
		}
		if next != identity {
			return errors.New("replay maintenance parent or authentication key changed")
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		batch, cancel := context.WithTimeout(ctx, o.Budget)
		result, e := sweep(batch, o.WorkParent, o.Keys, after, o.Limit, o.Apply)
		cancel()
		status := replayMaintenanceStatus(e)
		if err = emit(ReplayMaintenanceReport{pass, status, o.Apply, result}); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if status == "failed" || status == "interrupted" {
			return e
		}
		after = ""
		if result.More {
			after = result.Next
		}
		if err = wait(ctx, o.Interval); err != nil {
			return err
		}
	}
}

type replayMaintenanceIdentity struct {
	device, inode domain.U64
	bundleSHA     domain.Hash
}

// captureReplayMaintenanceIdentity は親inodeと鍵bundleの固定bytesを巡回開始時に固定する。
func captureReplayMaintenanceIdentity(o ReplayMaintenanceOptions) (replayMaintenanceIdentity, error) {
	return captureReplayMaintenanceIdentityMode(o, false)
}

// captureReplayMaintenanceIdentityMode は親と認証に使う鍵材料の固定bytesを束縛する。
func captureReplayMaintenanceIdentityMode(o ReplayMaintenanceOptions, independent bool) (replayMaintenanceIdentity, error) {
	dev, inode, e := replayRootIdentity(o.WorkParent)
	if e != nil {
		return replayMaintenanceIdentity{}, e
	}
	path, limit := filepath.Join(o.Keys, "bundle.json"), int64(backupKeysLimit)
	if independent {
		path, limit = o.Keys, 32
	}
	raw, e := readPrivate(path, limit)
	if e != nil {
		return replayMaintenanceIdentity{}, e
	}
	defer clear(raw)
	return replayMaintenanceIdentity{dev, inode, sha256.Sum256(raw)}, nil
}

func (v replayMaintenanceIdentity) check(o ReplayMaintenanceOptions) error {
	next, e := captureReplayMaintenanceIdentity(o)
	if e != nil {
		return e
	}
	if next != v {
		return errors.New("replay maintenance parent or key bundle changed")
	}
	return nil
}

func replayMaintenanceStatus(err error) string {
	switch {
	case err == nil:
		return "completed"
	case errors.Is(err, ErrReplaySweepRejected):
		return "needs_attention"
	case errors.Is(err, context.DeadlineExceeded):
		return "budget_exhausted"
	case errors.Is(err, context.Canceled):
		return "interrupted"
	default:
		return "failed"
	}
}

// waitReplayMaintenance は待機中の終了要求に応答し、実行が遅れた巡回を積み上げない。
func waitReplayMaintenance(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
