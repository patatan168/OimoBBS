// 共通分類の管理APIと通常フォームを同じ設定保存・取得・判定経路へ接続する。
package bootstrap

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"slices"
	"strconv"
	"strings"
)

type networkProbe struct {
	DNSStatus       string                `json:"dns_status"`
	ReverseResolved bool                  `json:"reverse_resolved"`
	Hostname        string                `json:"confirmed_hostname,omitempty"`
	Access          identity.AccessResult `json:"access"`
	IP              string                `json:"ip"`
	Class           identity.NetworkClass `json:"class"`
	Origin          string                `json:"origin"`
}
type networkView struct {
	CountryCount   int           `json:"country_count"`
	JapanCount     int           `json:"japan_count"`
	VPN4Count      int           `json:"vpn4_count"`
	VPN6Count      int           `json:"vpn6_count"`
	Config         NetworkConfig `json:"config"`
	Revision       domain.U64    `json:"revision"`
	Version        domain.U64    `json:"version"`
	Count          int           `json:"count"`
	LastAttempt    string        `json:"last_attempt"`
	LastSuccess    string        `json:"last_success"`
	Error          string        `json:"error_code"`
	Running        bool          `json:"running"`
	AppliedVersion domain.U64    `json:"applied_version"`
	Attempt        domain.Time   `json:"attempt_ns"`
}
type networksPage struct {
	View                           networkView
	ETag, CSRF, RequestID, Message string
	Fields                         url.Values
	PollAttempt                    domain.Time
	Invalid, Pending               bool
	Probe                          *networkProbe
	HostRules                      []identity.HostRule
}

var networksTemplate = webui.Template("networks")

func (r *Repository) networkView() (networkView, error) {
	r.mu.Lock()
	if e := r.available(); e != nil {
		r.mu.Unlock()
		return networkView{}, e
	}
	state := r.site.State()
	revision := state.Rows["network:active"].Revision
	if cached := r.networkViewCache; cached != nil && cached.Revision == revision {
		view := cached.copyForResponse(r.networkRunning.Load())
		r.mu.Unlock()
		return view, nil
	}
	r.mu.Unlock()
	v, e := loadNetworkState(state)
	if e != nil {
		return networkView{}, e
	}
	countryCount := 0
	japan, vpn4, vpn6 := 0, 0, 0
	if v.AccessData != nil {
		_, countryCount, _ = decodeCountries(v.AccessData.Countries)
		japan = len(v.AccessData.Japan)
		vpn4 = len(v.AccessData.VPN4)
		vpn6 = len(v.AccessData.VPN6)
	}
	view := networkView{CountryCount: countryCount, JapanCount: japan, VPN4Count: vpn4, VPN6Count: vpn6, Config: v.Config, Revision: state.Rows["network:active"].Revision, Version: v.Version, Count: len(v.Rows), LastAttempt: networkTime(int64(v.LastAttempt)), LastSuccess: networkTime(int64(v.LastSuccess)), Error: v.Error, Running: r.networkRunning.Load(), AppliedVersion: v.AppliedVersion, Attempt: v.LastAttempt}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return networkView{}, e
	}
	if r.site.State().Rows["network:active"].Revision == revision {
		r.networkViewCache = &view
	}
	return view.copyForResponse(r.networkRunning.Load()), nil
}

// copyForResponse は可変な設定スライスを分離し、取得中フラグだけを毎回の現在値にする。
func (v networkView) copyForResponse(running bool) networkView {
	v.Running = running
	v.Config.AccessOverrides = slices.Clone(v.Config.AccessOverrides)
	v.Config.Categories = slices.Clone(v.Config.Categories)
	v.Config.Sources = slices.Clone(v.Config.Sources)
	v.Config.Overrides = slices.Clone(v.Config.Overrides)
	return v
}

func (h *adminHandler) networkPage(w http.ResponseWriter, status int, s adminauth.Session, message string, fields url.Values, pending bool, probe *networkProbe, previousAttempt ...domain.Time) {
	v, e := h.repo.networkView()
	if e != nil {
		http.Error(w, "現在設定を取得できません。", 503)
		return
	}
	page := networksPage{HostRules: identity.ServiceHostRules(), View: v, ETag: networkETag(uint64(v.Revision)), CSRF: s.CSRF("/api/v1/networks"), RequestID: domain.NewID().String(), Message: message, Fields: fields, Invalid: status >= 400, Pending: pending, Probe: probe, PollAttempt: v.Attempt}
	if pending && len(previousAttempt) == 1 {
		page.PollAttempt = previousAttempt[0]
		if v.Attempt > previousAttempt[0] && !v.Running {
			page.Pending = false
		}
	}
	var out bytes.Buffer
	if executeAdminTemplate(w, &out, networksTemplate, page) != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(out.Bytes())
}

// networksRoutes はサイト管理者だけに共通表の編集を許可し、原URLや外部エラーを監査へ渡さない。
func (h *adminHandler) networksRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	api := strings.HasPrefix(r.URL.Path, "/api/")
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if r.Method == "GET" && path == "/networks" {
		if !api {
			h.networkPage(w, 200, s, "", nil, false, nil)
			return
		}
		v, e := h.repo.networkView()
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", networkETag(uint64(v.Revision)))
		w.Header().Set("X-CSRF-Token", s.CSRF("/api/v1/networks"))
		adminJSON(w, 200, map[string]any{"data": v})
		return
	}
	if api {
		h.networkAPI(w, r, s, path)
		return
	}
	if path != "/networks" || r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	fields, e := readNetworkForm(w, r)
	if e != nil {
		h.networkPage(w, 400, s, "入力形式を確認してください。", nil, false, nil)
		return
	}
	if !s.CheckCSRF("/api/v1/networks", fields.Get("csrf")) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	view, e := h.repo.networkView()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	action := fields.Get("action")
	if action == "probe" {
		probe, e := h.repo.probeNetworkContext(r.Context(), fields.Get("ip"))
		if e != nil {
			h.networkPage(w, 422, s, "IPv4またはIPv6のIPアドレスを入力してください。", fields, false, nil)
			return
		}
		h.networkPage(w, 200, s, "共通設定での判定結果です。板ごとの上書きはさらに優先します。", fields, false, &probe)
		return
	}
	if fields.Get("revision") != networkETag(uint64(view.Revision)) {
		h.networkPage(w, 412, s, "別の操作または自動更新で設定が変わりました。現在の設定を確認してから、もう一度操作してください。", fields, false, nil)
		return
	}
	if action == "refresh" {
		if len(view.Config.Sources) == 0 {
			h.networkPage(w, 422, s, "先に取得元を追加してください。", fields, false, nil)
			return
		}
		h.repo.wakeNetworkUpdater(true)
		h.networkPage(w, 200, s, "更新を受け付けました。完了すると画面を更新します。", nil, true, nil, view.Attempt)
		return
	}
	config, e := networkFormConfig(view.Config, fields)
	if e != nil {
		h.networkPage(w, 422, s, "入力を確認してください。CIDR・回線区分・取得元・更新間隔・カテゴリーに不正な値があります。説明は1024文字以内で入力してください。", fields, false, nil)
		return
	}
	duplicate, e := h.repo.changeNetworks(s, config, fields.Get("revision"), fields.Get("request_id"))
	if e != nil {
		h.failure(w, r, e)
		return
	}
	message := "設定を保存しました。手動の上書きは自動更新後も維持します。"
	if action == "standard_setup" {
		message = "無料の標準取得元を設定しました。取得が完了すると分類表が使われ、以後24時間ごとに自動更新します。"
	}
	if action == "domestic_setup" {
		message = "未登録の国内・VPN・クラウド・衛星・学術網の取得元を追加しました。既存の分類・上書き・更新間隔を維持して取得を開始します。"
	}
	if action == "category_delete" {
		message = "カテゴリーを削除しました。保存済みの回線割り当てと過去の投稿表示は保持しています。"
	}
	if duplicate {
		message = "保存済みの操作を確認しました。"
	}
	h.networkPage(w, 200, s, message, nil, config.Enabled, nil, view.Attempt)
}

func (h *adminHandler) networkAPI(w http.ResponseWriter, r *http.Request, s adminauth.Session, path string) {
	if r.Method != "PATCH" && r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		h.fail(w, r, 415, "JSON_REQUIRED")
		return
	}
	csrf, _, e := singleRequestHeader(r.Header, "X-CSRF-Token")
	if e != nil || !s.CheckCSRF("/api/v1/networks", csrf) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	if e != nil {
		h.fail(w, r, 400, "INVALID_JSON")
		return
	}
	if path == "/networks/lookup" && r.Method == "POST" {
		var in struct {
			IP string `json:"ip"`
		}
		if strictjson.Decode(raw, &in) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		p, e := h.repo.probeNetworkContext(r.Context(), in.IP)
		if e != nil {
			h.fail(w, r, 422, "INVALID_IP")
			return
		}
		adminJSON(w, 200, map[string]any{"data": p})
		return
	}
	etag, _, e := singleRequestHeader(r.Header, "If-Match")
	if e != nil {
		h.fail(w, r, 400, "INVALID_REVISION")
		return
	}
	if path == "/networks/refresh" && r.Method == "POST" {
		var empty struct{}
		if strictjson.Decode(raw, &empty) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		view, e := h.repo.networkView()
		if e != nil {
			h.failure(w, r, e)
			return
		}
		if etag != networkETag(uint64(view.Revision)) {
			h.fail(w, r, 412, "REVISION_CONFLICT")
			return
		}
		if len(view.Config.Sources) == 0 {
			h.fail(w, r, 422, "NETWORK_SOURCE_REQUIRED")
			return
		}
		h.repo.wakeNetworkUpdater(true)
		adminJSON(w, 202, map[string]any{"queued": true})
		return
	}
	if path != "/networks" || r.Method != "PATCH" {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	var config NetworkConfig
	if strictjson.Decode(raw, &config) != nil {
		h.fail(w, r, 400, "INVALID_JSON")
		return
	}
	key, _, e := singleRequestHeader(r.Header, "Idempotency-Key")
	if e != nil {
		h.fail(w, r, 400, "INVALID_REQUEST_KEY")
		return
	}
	duplicate, e := h.repo.changeNetworks(s, config, etag, key)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	view, e := h.repo.networkView()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	w.Header().Set("ETag", networkETag(uint64(view.Revision)))
	adminJSON(w, 200, map[string]any{"data": view, "duplicate": duplicate})
}

func (r *Repository) probeNetwork(raw string) (networkProbe, error) {
	ip, e := netip.ParseAddr(strings.TrimSpace(raw))
	if e != nil || ip.Zone() != "" {
		return networkProbe{}, errNetworkData
	}
	ip = ip.Unmap()
	t := r.liveNetworks.Load()
	out := networkProbe{IP: ip.String(), Class: t.Classify(nil, ip), Access: t.ClassifyAccess(ip), DNSStatus: string(r.networkHosts.DNSStatus(ip)), Origin: "未分類"}
	if t != nil {
		if _, ok := t.Overrides.Match(ip); ok {
			out.Origin = "管理者の共通上書き"
		} else if (out.DNSStatus == "absent" && out.Class.Suffix == "h") || (out.DNSStatus == "mismatch" && out.Class.Suffix == "H") {
			out.Origin = "DNSの確認結果による特殊表示"
		} else if out.Class.Kind == "vpn" || out.Class.Kind == "foreign" {
			out.Origin = "国・既知VPNの分類"
		} else if automatic, ok := t.Automatic.Match(ip); ok && specialNetworkKind(automatic.Kind) {
			out.Origin = "自動取得した共通表"
		} else if r.networkHosts.Hostname(ip) != "" {
			out.Origin = "逆引き・正引きで確認したサービス"
			out.Hostname = r.networkHosts.Hostname(ip)
		} else if _, ok := t.Automatic.Match(ip); ok {
			out.Origin = "自動取得した共通表"
		}
	}
	return out, nil
}

func readNetworkForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
	if e != nil {
		return nil, e
	}
	fields, e := url.ParseQuery(string(raw))
	if e != nil || len(fields["action"]) != 1 {
		return nil, errNetworkData
	}
	names := []string{"action", "csrf", "revision", "request_id"}
	extra := map[string][]string{"standard_setup": {}, "domestic_setup": {}, "access_setup": {}, "access_save": {"index", "cidr", "country", "country_code", "vpn"}, "access_delete": {"index"}, "category_save": {"index", "category_id", "name", "kind", "label", "suffix", "description", "provider"}, "category_delete": {"index"}, "settings": {"enabled", "interval_hours"}, "source_save": {"index", "preset", "display_preset", "name", "asn", "url", "kind", "label", "suffix", "provider"}, "source_delete": {"index"}, "override_save": {"index", "cidr", "display_preset", "kind", "label", "suffix", "provider"}, "override_delete": {"index"}, "refresh": {}, "probe": {"ip"}}
	more, ok := extra[fields.Get("action")]
	if !ok {
		return nil, errNetworkData
	}
	if !fields.Has("provider") {
		var filtered []string
		for _, name := range more {
			if name != "provider" {
				filtered = append(filtered, name)
			}
		}
		more = filtered
	}
	if fields.Get("action") == "access_save" && !fields.Has("country_code") {
		legacy := make([]string, 0, len(more))
		for _, name := range more {
			if name != "country_code" {
				legacy = append(legacy, name)
			}
		}
		more = legacy
	}
	if fields.Get("action") == "settings" && fields.Has("dns_mode") {
		more = append(more, "dns_mode")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return adminForm(w, r, 32<<10, append(names, more...)...)
}

// networkFormConfig は行単位の通常フォームを完全設定へ変換する。削除はCASでindexを固定する。
func networkFormConfig(config NetworkConfig, fields url.Values) (NetworkConfig, error) {
	config.Sources = append([]NetworkSource{}, config.Sources...)
	config.Overrides = append([]identity.NetworkClass{}, config.Overrides...)
	action := fields.Get("action")
	if action == "domestic_setup" {
		config = mergeDomesticNetworks(config)
		return config, config.validate()
	}
	if action == "standard_setup" {
		if len(config.Sources) != 0 {
			return config, errNetworkData
		}
		config.Sources = defaultNetworkSources()
		config.Enabled = true
		config.IntervalHours = 24
		return config, config.validate()
	}
	if action == "access_setup" {
		for _, source := range defaultAccessSources() {
			found := false
			for _, old := range config.Sources {
				if old.Type == source.Type {
					found = true
				}
			}
			if !found {
				config.Sources = append(config.Sources, source)
			}
		}
		config.Enabled = true
		return config, config.validate()
	}
	if action == "settings" {
		enabled, e := strconv.ParseBool(fields.Get("enabled"))
		if e != nil {
			return config, e
		}
		hours, e := strconv.ParseUint(fields.Get("interval_hours"), 10, 32)
		if e != nil {
			return config, e
		}
		if fields.Has("dns_mode") {
			config.DNSMode = fields.Get("dns_mode")
		}
		config.Enabled = enabled
		config.IntervalHours = uint32(hours)
		return config, config.validate()
	}
	index, e := strconv.Atoi(fields.Get("index"))
	if e != nil || index < -1 {
		return config, errNetworkData
	}
	switch action {
	case "access_save":
		config.AccessOverrides = append([]identity.AccessOverride{}, config.AccessOverrides...)
		cidr, e := canonicalNetworkCIDR(fields.Get("cidr"))
		if e != nil {
			return config, e
		}
		row := identity.AccessOverride{CIDR: cidr, Country: fields.Get("country"), CountryCode: strings.ToUpper(strings.TrimSpace(fields.Get("country_code"))), VPN: fields.Get("vpn")}
		if index == -1 {
			config.AccessOverrides = append(config.AccessOverrides, row)
		} else if index < len(config.AccessOverrides) {
			config.AccessOverrides[index] = row
		} else {
			return config, errNetworkData
		}
	case "access_delete":
		if index < 0 || index >= len(config.AccessOverrides) {
			return config, errNetworkData
		}
		config.AccessOverrides = append(append([]identity.AccessOverride{}, config.AccessOverrides[:index]...), config.AccessOverrides[index+1:]...)
		if len(config.AccessOverrides) == 0 {
			config.AccessOverrides = nil
		}
	case "category_save":
		row := NetworkCategory{Provider: fields.Get("provider"), Description: fields.Get("description"), ID: strings.TrimSpace(fields.Get("category_id")), Name: strings.TrimSpace(fields.Get("name")), Kind: fields.Get("kind"), Label: fields.Get("label"), Suffix: fields.Get("suffix")}
		config.Categories = append([]NetworkCategory{}, config.Categories...)
		if index == -1 {
			config.Categories = append(config.Categories, row)
		} else if index < len(config.Categories) {
			config.Categories[index] = row
		} else {
			return config, errNetworkData
		}
	case "category_delete":
		config.Categories = append([]NetworkCategory{}, config.Categories...)
		if index < 0 || index >= len(config.Categories) {
			return config, errNetworkData
		}
		config.Categories = append(config.Categories[:index], config.Categories[index+1:]...)
	case "source_save":
		source, e := networkSourceForm(fields)
		if e == nil && source.Type == "asn" {
			e = applyDisplayPreset(config.Categories, fields.Get("display_preset"), &source.Kind, &source.Label, &source.Suffix)
		}
		if e != nil {
			return config, e
		}
		applyProviderPreset(config.Categories, fields.Get("display_preset"), &source.Provider)
		if index == -1 {
			config.Sources = append(config.Sources, source)
		} else if index < len(config.Sources) {
			config.Sources[index] = source
		} else {
			return config, errNetworkData
		}
	case "source_delete":
		if index < 0 || index >= len(config.Sources) {
			return config, errNetworkData
		}
		config.Sources = append(config.Sources[:index], config.Sources[index+1:]...)
		if len(config.Sources) == 0 {
			config.Enabled = false
		}
	case "override_save":
		cidr, e := canonicalNetworkCIDR(fields.Get("cidr"))
		if e != nil {
			return config, e
		}
		row := identity.NetworkClass{Provider: fields.Get("provider"), CIDR: cidr, Kind: fields.Get("kind"), Label: fields.Get("label"), Suffix: fields.Get("suffix")}
		if e := applyDisplayPreset(config.Categories, fields.Get("display_preset"), &row.Kind, &row.Label, &row.Suffix); e != nil {
			return config, e
		}
		applyProviderPreset(config.Categories, fields.Get("display_preset"), &row.Provider)
		label, suffix := identity.DefaultNetworkDisplay(row.Kind)
		if row.Label == "" {
			row.Label = label
		}
		if row.Suffix == "" {
			row.Suffix = suffix
		}
		if index == -1 {
			config.Overrides = append(config.Overrides, row)
		} else if index < len(config.Overrides) {
			config.Overrides[index] = row
		} else {
			return config, errNetworkData
		}
	case "override_delete":
		if index < 0 || index >= len(config.Overrides) {
			return config, errNetworkData
		}
		config.Overrides = append(config.Overrides[:index], config.Overrides[index+1:]...)
	default:
		return config, errNetworkData
	}
	return config, config.validate()
}

func networkSourceForm(f url.Values) (NetworkSource, error) {
	s := NetworkSource{Provider: strings.TrimSpace(f.Get("provider")), Name: strings.TrimSpace(f.Get("name")), Type: "asn", Kind: f.Get("kind"), Label: f.Get("label"), Suffix: f.Get("suffix")}
	switch f.Get("preset") {
	case "japan", "vpn", "countries":
		for _, source := range defaultAccessSources() {
			if source.Type == f.Get("preset") {
				s = source
				if strings.TrimSpace(f.Get("name")) != "" {
					s.Name = strings.TrimSpace(f.Get("name"))
				}
				return s, nil
			}
		}
	case "csv":
		s.Type = "csv"
		s.URL = strings.TrimSpace(f.Get("url"))
		s.Kind = ""
		s.Label = ""
		s.Suffix = ""
		s.Provider = ""
		if s.Name == "" {
			s.Name = "分類CSV"
		}
	case "asn":
		asn, e := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(f.Get("asn"))), "AS"), 10, 32)
		if e != nil {
			return s, e
		}
		s.ASN = uint32(asn)
		if s.Name == "" {
			s.Name = "ASN " + strconv.FormatUint(asn, 10)
		}
	default:
		found := false
		for _, preset := range networkSourcePresets {
			if preset.ID != f.Get("preset") {
				continue
			}
			found = true
			s.ASN = preset.ASN
			if s.Provider == "" {
				s.Provider = presetProvider(preset.ID)
			}
			if s.Name == "" {
				s.Name = preset.Name
			}
			if s.Kind == "" {
				s.Kind = preset.Kind
			}
			if s.Label == "" {
				s.Label = preset.Label
			}
			if s.Suffix == "" {
				s.Suffix = preset.Suffix
			}
			break
		}
		if !found {
			return s, errNetworkData
		}
	}
	if s.Kind == "" && s.Type == "asn" {
		s.Kind = "unknown"
	}
	if s.Type == "asn" {
		label, suffix := identity.DefaultNetworkDisplay(s.Kind)
		if s.Label == "" {
			s.Label = label
		}
		if s.Suffix == "" {
			s.Suffix = suffix
		}
	}
	return s, nil
}

type networkRowForm struct {
	Page   networksPage
	Fields url.Values
}

// SourceForm は失敗した入力を同じ編集行へ戻し、それ以外の行は保存済み設定から表示する。
func (p networksPage) SourceForm(index int, source NetworkSource) networkRowForm {
	preset := source.Type
	if preset == "" {
		preset = "docomo"
	}
	kind := source.Kind
	if kind == "" {
		kind = ""
	}
	fields := url.Values{"index": {strconv.Itoa(index)}, "preset": {preset}, "display_preset": {"custom"}, "name": {source.Name}, "asn": {strconv.FormatUint(uint64(source.ASN), 10)}, "url": {source.URL}, "kind": {kind}, "label": {source.Label}, "suffix": {source.Suffix}, "provider": {source.Provider}}
	if source.ASN == 0 {
		fields.Set("asn", "")
	}
	if p.Fields.Get("action") == "source_save" && p.Fields.Get("index") == strconv.Itoa(index) {
		fields = p.Fields
	}
	return networkRowForm{Page: p, Fields: fields}
}

// OverrideForm は回線行の入力を保持する。空の名前/末尾は回線区分の既定値を使う。
func (p networksPage) OverrideForm(index int, row identity.NetworkClass) networkRowForm {
	kind := row.Kind
	if kind == "" {
		kind = "fixed"
	}
	fields := url.Values{"index": {strconv.Itoa(index)}, "cidr": {row.CIDR}, "display_preset": {"custom"}, "kind": {kind}, "label": {row.Label}, "suffix": {row.Suffix}, "provider": {row.Provider}}
	if p.Fields.Get("action") == "override_save" && p.Fields.Get("index") == strconv.Itoa(index) {
		fields = p.Fields
	}
	return networkRowForm{Page: p, Fields: fields}
}

func (p networksPage) NewSourceForm() networkRowForm { return p.SourceForm(-1, NetworkSource{}) }
func (p networksPage) NewOverrideForm() networkRowForm {
	return p.OverrideForm(-1, identity.NetworkClass{})
}
