// サーバーの初回起動で標準取得元を保存し、通常の更新ワーカーへ取得を依頼する。
package bootstrap

import "net/http"

// EnsureStandardNetworks は未設定サイトだけで国内回線・国・VPNの24時間更新を有効にする。
// 保存済みの設定（明示的な無効化を含む）は変更しない。取得失敗でもサーバーは起動できる。
// clientは検証用の差し替え。nilなら既存の公開HTTPS専用クライアントを維持する。
func (r *Repository) EnsureStandardNetworks(client *http.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return err
	}
	current, err := loadNetworkState(r.site.State())
	if err != nil {
		return err
	}
	if current.Version != 0 {
		return nil
	}
	if client != nil {
		r.networkClient = client
	}
	current.Version = 1
	current.Config.Sources = defaultNetworkSources()
	current.Config.Enabled = true
	if err := r.publishNetworks(current, nil, "network_standard_setup", nil); err != nil {
		return err
	}
	r.wakeNetworkUpdater(false)
	return nil
}

// mergeDomesticNetworks は未登録の標準ASN・国/VPNとカテゴリーだけを加える。
// 既存の同一ASN設定・カテゴリー・手動上書き・更新間隔は維持する。
func mergeDomesticNetworks(config NetworkConfig) NetworkConfig {
	config.Sources = append([]NetworkSource{}, config.Sources...)
	config.Categories = append([]NetworkCategory{}, config.Categories...)
	sources := map[string]bool{}
	for _, source := range config.Sources {
		sources[networkSourceKey(source)] = true
	}
	for _, source := range defaultNetworkSources() {
		if !sources[networkSourceKey(source)] {
			config.Sources = append(config.Sources, source)
		}
	}
	categories := map[string]bool{}
	for _, category := range config.Categories {
		categories[category.ID] = true
	}
	for _, category := range defaultNetworkCategories() {
		if !categories[category.ID] {
			config.Categories = append(config.Categories, category)
		}
	}
	config.Enabled = true
	return config
}
