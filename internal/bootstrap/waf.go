// WAFの設定を監査付きで保存し、要求ごとの検査へ稼働中に反映する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/waf"
)

const wafReader uint32 = 91

// WAFSettings は公開・管理要求の追加検査と大量アクセス制限。未保存では全体OFF。
type WAFSettings struct {
	Enabled bool                `json:"enabled"`
	Traffic waf.TrafficSettings `json:"traffic"`
}

// UnmarshalJSON は旧ON/OFF形式を読み、新形式では全制限項目を厳密に要求する。
func (v *WAFSettings) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(raw, &fields); err != nil {
		return err
	}
	if _, ok := fields["traffic"]; !ok {
		var legacy struct {
			Enabled bool `json:"enabled"`
		}
		if err := strictjson.Decode(raw, &legacy); err != nil {
			return err
		}
		*v = WAFSettings{Enabled: legacy.Enabled, Traffic: waf.DefaultTrafficSettings()}
		return nil
	}
	type plain WAFSettings
	var parsed plain
	if err := strictjson.Decode(raw, &parsed); err != nil {
		return err
	}
	if !parsed.Traffic.Valid() {
		return fmt.Errorf("invalid traffic limits")
	}
	*v = WAFSettings(parsed)
	return nil
}

func (r *Repository) wafSettings() WAFSettings {
	if value := r.liveWAF.Load(); value != nil {
		return *value
	}
	return WAFSettings{Traffic: waf.DefaultTrafficSettings()}
}

// 頻度計算には単調時計だけが必要。毎要求の壁時計読取りを避け、補充を逆行させない。
var trafficClockOrigin = time.Now()

func trafficNow() time.Time { return trafficClockOrigin.Add(time.Since(trafficClockOrigin)) }

// publishWAF は保存済み設定を公開する。既存の処理枠と消費量は引き継ぐ。
func (r *Repository) publishWAF(value WAFSettings) {
	now := trafficNow()
	r.publicTraffic.Configure(value.Traffic, now)
	r.adminTraffic.Configure(value.Traffic, now)
	r.liveWAF.Store(&value)
}

func wafMinimumReader(raw json.RawMessage) uint32 {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if rawTraffic, ok := fields["traffic"]; ok {
		var traffic map[string]json.RawMessage
		_ = json.Unmarshal(rawTraffic, &traffic)
		if _, configured := traffic["client_enabled"]; configured {
			return wafReader
		}
		if _, configured := traffic["posting"]; configured {
			return 88
		}
		return 87
	}
	return 86
}

// AdminWAF は保存版と、現在のプロセスで拒否した要求の総数を返す。
type AdminWAF struct {
	Settings      WAFSettings      `json:"settings"`
	Revision      domain.U64       `json:"revision"`
	Blocked       uint64           `json:"blocked"`
	PublicTraffic waf.TrafficStats `json:"public_traffic"`
	AdminTraffic  waf.TrafficStats `json:"admin_traffic"`
}

// ETag は遮断件数の変化に影響されない設定保存用の版を返す。
func (v AdminWAF) ETag() string { return fmt.Sprintf(`"waf:%d"`, v.Revision) }

func validateWAFValue(key string, raw json.RawMessage) error {
	var value WAFSettings
	if key != "active" || strictjson.Decode(raw, &value) != nil {
		return store.ErrCorrupt
	}
	return nil
}

// wafViewLocked はサイトmutex所有中に現在設定と保存版を取り出す。
func (r *Repository) wafViewLocked() AdminWAF {
	return AdminWAF{Settings: r.wafSettings(), Revision: r.site.State().Rows["waf:active"].Revision, Blocked: r.wafBlocked.Load(), PublicTraffic: r.publicTraffic.Stats(), AdminTraffic: r.adminTraffic.Stats()}
}

// updateWAF は再認証・CSRF確認後の入力を再送/CAS/監査付きSyncで確定する。サイトmutexを所有する。
func (r *Repository) updateWAF(s adminauth.Session, value WAFSettings, etag, key string) (AdminWAF, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !value.Traffic.Valid() {
		return AdminWAF{}, &adminFailure{status: 422, code: "INVALID_WAF"}
	}
	if err := r.currentAdministrator(s); err != nil {
		return AdminWAF{}, err
	}
	if err := r.available(); err != nil {
		return AdminWAF{}, err
	}
	if !s.Reauthenticated(time.Now()) {
		return AdminWAF{}, &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
	}
	if !adminRequestKey.MatchString(key) {
		return AdminWAF{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminWAF{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return AdminWAF{}, err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return AdminWAF{}, err
	}
	defer clear(secret[:])
	requestKey := identity.MAC(secret[:], "oimo/admin-key/v1", s.Admin[:], []byte(key))
	raw, _ := json.Marshal(value)
	request := identity.MAC(secret[:], "oimo/waf-update/v1", s.Admin[:], raw, []byte(etag))
	now := domain.Time(time.Now().UnixNano())
	state := r.site.State()
	if prior, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var receipt adminReceipt
		if err = strictjson.Decode(prior.Value, &receipt); err != nil {
			return AdminWAF{}, err
		}
		if receipt.Created > now {
			return AdminWAF{}, ErrControlExpiryClock
		}
		if receipt.Expires > now {
			if receipt.Request != request {
				return AdminWAF{}, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			return AdminWAF{Settings: value, Revision: receipt.Revision, Blocked: r.wafBlocked.Load(), PublicTraffic: r.publicTraffic.Stats(), AdminTraffic: r.adminTraffic.Stats()}, nil
		}
	}
	if r.wafViewLocked().ETag() != etag {
		return AdminWAF{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) {
		return AdminWAF{}, ErrPostingUnavailable
	}
	var site siteState
	if err = strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return AdminWAF{}, err
	}
	site.MinimumReader = max(site.MinimumReader, wafReader)
	id := domain.NewID()
	receipt := adminReceipt{ID: id, Admin: s.Admin, Key: requestKey, Request: request, Name: "WAF", Revision: state.Seq + 1, Created: now, Expires: now + 86400e9}
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("waf", "active", value, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
	kid := uint32(8)
	frame, err := controlFrame(state, id, now, "waf_update", changes, []string{site.ID.String()}, domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "waf_update", Request: &request, Idempotency: &requestKey, KeyID: &kid})
	if err != nil {
		return AdminWAF{}, err
	}
	if r.site.Append(frame).Status != store.Durable {
		r.stopped = true
		return AdminWAF{}, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	r.publishWAF(value)
	return r.wafViewLocked(), nil
}

// wafHandler はOFFなら追加検査をせず、ONなら本文受信・ルーティングより前に拒否する。
// 遮断件数だけをメモリで集計し、IP・Cookie・本文・攻撃文字列を追加保存しない。
func (r *Repository) wafHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.wafSettings().Enabled {
			if reason := waf.Inspect(req); reason != "" {
				r.recordWAF(req, reason)
				r.rejectWAF(w, req)
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}

// trafficHandler は検証済みの利用者アドレスで、本文受信前に処理枠を取得する。
// 公開側と管理側を分離し、公開側の混雑による設定画面の枠消費を防ぐ。
func (r *Repository) trafficHandler(next http.Handler, admin bool) http.Handler {
	guard := &r.publicTraffic
	base := ""
	if admin {
		guard = &r.adminTraffic
		if r.cfg.Admin.Transport == "public_path" {
			_, base, _ = r.cfg.adminEndpoint()
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		policy := r.wafSettings()
		if !policy.Enabled || !policy.Traffic.Enabled {
			next.ServeHTTP(w, req)
			return
		}
		endpoint, err := netip.ParseAddrPort(req.RemoteAddr)
		ip := endpoint.Addr()
		if err != nil {
			ip, _ = netip.ParseAddr(req.RemoteAddr)
		}
		release, decision := guard.AcquireOperation(ip, wafOperation(req, admin, base), trafficNow())
		if decision.Status != 0 {
			r.recordWAF(req, "traffic_limit")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", strconv.Itoa(decision.RetryAfter))
			http.Error(w, "アクセスが集中しています。少し待ってから再試行してください。", decision.Status)
			return
		}
		defer release()
		next.ServeHTTP(w, req)
	})
}

// wafOperation は本文・クエリを読まず、実際の公開/管理入口に一致する処理だけを分類する。
func wafOperation(req *http.Request, admin bool, base string) waf.Operation {
	path := req.URL.Path
	if admin {
		if base != "" {
			if !strings.HasPrefix(path, base+"/") {
				return waf.Ordinary
			}
			path = strings.TrimPrefix(path, base)
		}
		if req.Method == http.MethodGet && path == otpRoute+"register/qr" {
			return waf.Authentication
		}
		if req.Method == http.MethodPost && (path == "/login" || path == "/reauth" || path == "/api/v1/reauth" || strings.HasPrefix(path, "/api/v1/passkey/") || strings.HasPrefix(path, otpRoute) || path == "/api/v1/password" || path == "/password" || (strings.HasPrefix(path, "/administrators/") || strings.HasPrefix(path, "/api/v1/administrators/")) && strings.HasSuffix(path, "/password-reset")) {
			return waf.Authentication
		}
		return waf.Ordinary
	}
	if path == "/search" {
		return waf.Search
	}
	if path == "/reports" || path == "/reports/lookup" {
		return waf.Reports
	}
	if req.Method == http.MethodPost && (path == "/test/bbs.cgi" || path == "/web/post") {
		return waf.Posting
	}
	return waf.Ordinary
}
