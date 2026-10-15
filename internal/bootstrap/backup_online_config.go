// 独立した定期バックアップ設定を検証し、稼働サービスと運用APIから同じ工程を使う。
package bootstrap

import (
	"errors"
	"oimobbs/internal/strictjson"
	"time"
)

// OnlineBackupConfig はprivateな親/信頼根と実行上限。設定だけで本番データの回収を開始しない。
// 作成はApply、署名済み期限回収はReclaimで明示し、それぞれ独立にプレビューできる。
type OnlineBackupConfig struct {
	CleanupKey            string `json:"cleanup_key"`
	CopyParent            string `json:"copy_parent"`
	KeysParent            string `json:"keys_parent"`
	PartialPlanParent     string `json:"partial_plan_parent"`
	PartialKeysPlanParent string `json:"partial_keys_plan_parent"`
	KeysPlanParent        string `json:"keys_plan_parent"`
	PairPlanParent        string `json:"pair_plan_parent"`
	WorkParent            string `json:"work_parent"`
	ControlParent         string `json:"control_parent"`
	TrustInstance         string `json:"trust_instance"`
	IntervalSeconds       int    `json:"interval_seconds"`
	BudgetSeconds         int    `json:"budget_seconds"`
	Apply                 bool   `json:"apply"`
	Reclaim               bool   `json:"reclaim"`
	MaxBytes              uint64 `json:"max_bytes"`
	MaxOwners             int    `json:"max_owners"`
	MaxBoards             int    `json:"max_boards"`
}

// LoadOnlineBackupConfig は64KiB以内の所有者限定JSONを読み、起動前に全配置と上限を検査する。
func LoadOnlineBackupConfig(path string, cfg Config) (OnlineBackupConfig, error) {
	var value OnlineBackupConfig
	raw, e := readPrivate(path, 64<<10)
	if e != nil {
		return value, e
	}
	if e = strictjson.Decode(raw, &value); e != nil {
		return value, e
	}
	if value.IntervalSeconds < 3600 || value.IntervalSeconds > 86400 {
		return value, errors.New("online backup interval requires 1h..24h")
	}
	o, capture := value.Options()
	if e = validatePreparationMaintenance(cfg, o); e != nil {
		return value, e
	}
	if _, _, e = normalizeOnlineSiteOptions(capture); e != nil {
		return value, e
	}
	return value, nil
}

// Options は秒数を有界検証前のdurationへ変換し、作成用の共有optionsを返す。
func (c OnlineBackupConfig) Options() (BackupPreparationMaintenanceOptions, OnlineBackupSiteOptions) {
	o := BackupPreparationMaintenanceOptions{CopyParent: c.CopyParent, KeysParent: c.KeysParent, PartialPlanParent: c.PartialPlanParent, PartialKeysPlanParent: c.PartialKeysPlanParent, KeysPlanParent: c.KeysPlanParent, PairPlanParent: c.PairPlanParent, WorkParent: c.WorkParent, ControlParent: c.ControlParent, TrustInstance: c.TrustInstance, Apply: c.Apply, Reclaim: c.Reclaim}
	o.CleanupKey = c.CleanupKey
	// 検査前の整数overflowを避け、不正な値は検証器へ渡す零値にする。
	if c.IntervalSeconds >= 3600 && c.IntervalSeconds <= 86400 {
		o.Interval = time.Duration(c.IntervalSeconds) * time.Second
	}
	if c.BudgetSeconds >= 1 && c.BudgetSeconds <= 3600 {
		o.Budget = time.Duration(c.BudgetSeconds) * time.Second
	}
	return o, OnlineBackupSiteOptions{MaxBytes: c.MaxBytes, MaxOwners: c.MaxOwners, MaxBoards: c.MaxBoards}
}
