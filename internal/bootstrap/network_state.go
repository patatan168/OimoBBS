// 共通分類の取得設定・成功済み表・失敗状態を一つの耐久値として検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"slices"
	"strings"
)

const networkRowLimit = 40000
const networkSourceLimit = 256
const networkCategoryLimit = 256

// NetworkSource は取得元とASN単位の分類。CSVの場合は行内の分類を使用する。
type NetworkSource struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	ASN      uint32 `json:"asn"`
	URL      string `json:"url"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Suffix   string `json:"suffix"`
}

// NetworkConfig は共通自動表の設定。Overridesは更新で消さない運営の修正。
type NetworkConfig struct {
	DNSMode         string                    `json:"dns_mode"`
	AccessOverrides []identity.AccessOverride `json:"access_overrides"`
	Categories      []NetworkCategory         `json:"categories"`
	Enabled         bool                      `json:"enabled"`
	IntervalHours   uint32                    `json:"interval_hours"`
	Sources         []NetworkSource           `json:"sources"`
	Overrides       []identity.NetworkClass   `json:"overrides"`
}

type networkState struct {
	AccessData     *networkAccessData `json:"access_data"`
	Version        domain.U64         `json:"version"`
	Config         NetworkConfig      `json:"config"`
	Rows           networkRows        `json:"rows"`
	LastAttempt    domain.Time        `json:"last_attempt_ns"`
	LastSuccess    domain.Time        `json:"last_success_ns"`
	AttemptVersion domain.U64         `json:"attempt_version"`
	AppliedVersion domain.U64         `json:"applied_version"`
	Error          string             `json:"error_code"`
}

func defaultNetworkConfig() NetworkConfig {
	return NetworkConfig{Categories: defaultNetworkCategories(), IntervalHours: 24, Sources: []NetworkSource{}, Overrides: []identity.NetworkClass{}}
}

// validate は秘密付きURLや重複取得元、不正な回線表示を保存前に拒否する。
func (v NetworkConfig) validate() error {
	if (v.DNSMode != "" && v.DNSMode != "system" && v.DNSMode != "google_https") || identity.ValidateAccessOverrides(v.AccessOverrides) != nil || validateNetworkCategories(v.Categories) != nil || v.IntervalHours < 1 || v.IntervalHours > 168 || v.Sources == nil || len(v.Sources) > networkSourceLimit || v.Overrides == nil || identity.ValidateNetworks(v.Overrides) != nil || v.Enabled && len(v.Sources) == 0 {
		return store.ErrCorrupt
	}
	seen := map[string]bool{}
	seenSource := map[string]bool{}
	for _, s := range v.Sources {
		if !identity.ValidProvider(s.Provider) || s.Type != "asn" && s.Provider != "" {
			return store.ErrCorrupt
		}
		if !validName(s.Name) || seen[s.Name] {
			return store.ErrCorrupt
		}
		seen[s.Name] = true
		sourceID := networkSourceKey(s)
		if seenSource[sourceID] {
			return store.ErrCorrupt
		}
		seenSource[sourceID] = true
		switch s.Type {
		case "asn":
			if s.ASN == 0 || s.ASN == ^uint32(0) || s.URL != "" || identity.ValidateNetworks([]identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: s.Kind, Label: s.Label, Suffix: s.Suffix}}) != nil {
				return store.ErrCorrupt
			}
		case "japan", "vpn", "countries":
			if s.ASN != 0 || s.URL != "" || s.Kind != "" || s.Label != "" || s.Suffix != "" {
				return store.ErrCorrupt
			}
		case "csv":
			if !validNetworkURL(s.URL) || s.ASN != 0 || s.Kind != "" || s.Label != "" || s.Suffix != "" {
				return store.ErrCorrupt
			}
		default:
			return store.ErrCorrupt
		}
	}
	return nil
}

func validNetworkURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && len(raw) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && !strings.Contains(raw, "#") && u.Opaque == "" && !strings.HasSuffix(u.Host, ":") && (u.Port() == "" || u.Port() == "443")
}

func (v networkState) validate() error {
	if v.Version == 0 || v.Config.validate() != nil || v.Rows == nil || v.LastAttempt < 0 || v.LastSuccess < 0 || v.LastSuccess > v.LastAttempt || v.AttemptVersion > v.Version || v.AppliedVersion > v.Version || (v.LastAttempt == 0) != (v.AttemptVersion == 0) || (v.LastSuccess == 0) != (v.AppliedVersion == 0) || (v.LastSuccess == 0) != (len(v.Rows) == 0 && v.AccessData == nil) || !slices.Contains([]string{"", "fetch_failed", "invalid_data"}, v.Error) {
		return store.ErrCorrupt
	}
	if _, e := compileAccessData(v.AccessData, v.Config.AccessOverrides); e != nil {
		return e
	}
	_, e := identity.CompileNetworks(v.Rows, networkRowLimit)
	return e
}

func validateNetworkValue(key string, old, next json.RawMessage) error {
	var v networkState
	if key != "active" || strictjson.DecodeLimit(next, &v, store.MaxNetworkValueJSON) != nil || v.validate() != nil {
		return store.ErrCorrupt
	}
	if len(old) > 0 {
		var p networkState
		if strictjson.DecodeLimit(old, &p, store.MaxNetworkValueJSON) != nil || v.Version < p.Version || v.Version > p.Version+1 || v.LastAttempt < p.LastAttempt || v.LastSuccess < p.LastSuccess {
			return store.ErrCorrupt
		}
		if v.Version == p.Version && !reflect.DeepEqual(v.Config, p.Config) {
			return store.ErrCorrupt
		}
		if v.Version != p.Version && (!reflect.DeepEqual(v.AccessData, p.AccessData) || !reflect.DeepEqual(v.Rows, p.Rows) || v.LastAttempt != p.LastAttempt || v.LastSuccess != p.LastSuccess || v.AppliedVersion != p.AppliedVersion || v.AttemptVersion != p.AttemptVersion || v.Error != p.Error) {
			return store.ErrCorrupt
		}
	}
	return nil
}

func loadNetworkState(state store.ControlState) (networkState, error) {
	if row, ok := state.Rows["network:active"]; ok {
		var v networkState
		e := strictjson.DecodeLimit(row.Value, &v, store.MaxNetworkValueJSON)
		if e != nil {
			return v, e
		}
		return v, v.validate()
	}
	return networkState{Config: defaultNetworkConfig(), Rows: []identity.NetworkClass{}}, nil
}

func compileNetworkState(v networkState) (*identity.NetworkClassifier, error) {
	auto, e := identity.CompileNetworks(v.Rows, networkRowLimit)
	if e != nil {
		return nil, e
	}
	overrides, e := identity.CompileNetworks(v.Config.Overrides, 512)
	if e != nil {
		return nil, e
	}
	access, e := compileAccessData(v.AccessData, v.Config.AccessOverrides)
	if e != nil {
		return nil, e
	}
	return &identity.NetworkClassifier{Automatic: auto, Overrides: overrides, Access: access}, nil
}

// networkSourceKey は表示名と独立した取得対象の同一性を返す。
func networkSourceKey(source NetworkSource) string {
	if source.Type == "asn" {
		return fmt.Sprint("asn:", source.ASN)
	}
	return source.Type + ":" + source.URL
}

// networkRequiresReader81 は国内取得元の拡張上限を必要とする保存状態を識別する。
func networkRequiresReader81(state networkState) bool {
	return len(state.Config.Sources) > 16 || len(state.Config.Categories) > 128
}
