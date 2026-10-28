// 共通閲覧・板閲覧・管理画面の接続条件を同じHTMLフォーム/APIで編集する。
package bootstrap

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
)

// readingRoute は既知の設定URLだけをスコープへ変換する。
func readingRoute(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/api/v1")
	if path == "/reading" {
		return "site", true
	}
	if path == "/admin-access" {
		return "admin", true
	}
	parts := strings.Split(path, "/")
	if len(parts) == 4 && parts[1] == "boards" && parts[3] == "reading" {
		id, err := readingScope(parts[2])
		if err == nil && id != (domain.ID{}) {
			return parts[2], true
		}
	}
	return "", false
}
func isReadingRoute(path string) bool { _, ok := readingRoute(path); return ok }

type readingPage struct {
	Master                                                     *AdminReading
	BoardSettings                                              string
	State                                                      AdminReading
	Title, Description, Action, CSRF, RequestID, Peer, Message string
	Values                                                     url.Values
	Kinds                                                      []ruleFieldOption
	Countries                                                  []string
}

// KindAllowed は保存値または再表示する入力を回線チェックへ戻す。
func (p readingPage) KindAllowed(kind string) bool {
	return p.DisplayValue("allow_"+kind) == "true"
}

var readingTemplate = webui.Template("reading")

// readingRoutes はHTMLの入力保持とAPIの厳格JSONに、経路別CSRF・CASを適用する。
func (h *adminHandler) readingRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	scope, _ := readingRoute(r.URL.Path)
	action := strings.TrimPrefix(r.URL.Path, "/api/v1")
	route := "/api/v1" + action
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	current, err := h.repo.adminReading(s, scope)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if r.Method == "GET" {
		w.Header().Set("ETag", current.ETag())
		w.Header().Set("X-CSRF-Token", s.CSRF(route))
		if api {
			adminJSON(w, 200, map[string]any{"data": current})
			return
		}
		h.writeReadingPage(w, r, s, current, action, 200, "", nil)
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var p ReadingPolicy
	var etag, key string
	var fields url.Values
	if api {
		csrf, _, e := singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil || !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, _, e = singleRequestHeader(r.Header, "If-Match")
		if e != nil {
			h.fail(w, r, 400, "INVALID_REVISION")
			return
		}
		key, _, e = singleRequestHeader(r.Header, "Idempotency-Key")
		if e != nil {
			h.fail(w, r, 400, "INVALID_REQUEST_KEY")
			return
		}
		typ, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, _, parseErr := mime.ParseMediaType(typ)
		if e != nil || parseErr != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if e != nil || strictjson.Decode(raw, &p) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		fields, err = readingForm(w, r)
		if err != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF(route, fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		p, err = readingFormPolicy(fields)
		if err != nil {
			h.writeReadingPage(w, r, s, current, action, 422, "入力を確認してください。IP/CIDR・国コード・UAは各行に1つ指定します。", fields)
			return
		}
		etag, key = fields.Get("revision"), fields.Get("request_id")
	}
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	if scope == "admin" && p.Enabled && (p.Network.denyUnresolvedHost() || len(p.Network.DeniedKinds) > 0) {
		h.repo.resolveNetworkHost(r.Context(), peer.Addr(), true)
	}
	result, err := h.repo.updateReading(s, scope, p, etag, key, peer.Addr(), r.UserAgent())
	if err != nil {
		if !api {
			if failure, ok := err.(*adminFailure); ok && failure.status == 422 {
				message := "入力を確認してください。"
				if failure.code == "ADMIN_SELF_LOCKOUT" {
					message = "現在の接続元が拒否されるため保存しませんでした。許可IP・国・回線・VPNの条件を確認してください。"
				}
				h.writeReadingPage(w, r, s, AdminReading{scope, p, current.Revision}, action, 422, message, fields)
				return
			}
		}
		h.failure(w, r, err)
		return
	}
	w.Header().Set("ETag", result.ETag())
	if api {
		adminJSON(w, 200, map[string]any{"data": result})
		return
	}
	http.Redirect(w, r, action, 303)
}

// writeReadingPage は既存値または拒否した入力を再表示する。CSRFと再送キーを保持する。
func (h *adminHandler) writeReadingPage(w http.ResponseWriter, r *http.Request, s adminauth.Session, v AdminReading, action string, status int, message string, fields url.Values) {
	title, description := "掲示板全体の閲覧制限", "板の閲覧条件にも、この共通条件が適用されます。Web・専ブラ用DAT・一覧・検索を対象にします。閲覧を拒否した接続元は投稿もできません。投稿だけの制限は投稿設定で管理します。"
	if v.Scope == "admin" {
		title = "管理画面のアクセス制限"
		description = "管理画面に接続できる回線やIPを設定します。ログイン画面・管理ページ・APIが対象です。"
	} else if v.Scope != "site" {
		title = "板の閲覧制限"
		h.repo.mu.Lock()
		if id, err := readingScope(v.Scope); err == nil {
			if board := h.repo.posting[id]; board != nil {
				title += "：" + board.boardName() + "（" + board.boardKey() + "）"
			}
		}
		h.repo.mu.Unlock()
		description = "この板のWeb・DAT・一覧・検索を対象にします。閲覧には掲示板全体とこの板の両方の条件を満たす必要があります。拒否した板はその接続元の板一覧・メニュー・検索から除き、投稿も拒否します。"
	}
	if fields == nil {
		fields = url.Values{"revision": {v.ETag()}, "request_id": {domain.NewID().String()}, "enabled": {fmtBool(v.Policy.Enabled)}, "allowed_cidrs": {strings.Join(v.Policy.AllowedCIDRs, "\n")}, "denied_cidrs": {strings.Join(v.Policy.DeniedCIDRs, "\n")}, "denied_agents": {strings.Join(v.Policy.DeniedAgents, "\n")}, "denied_countries": {strings.Join(v.Policy.Network.DeniedCountries, "\n")}, "japan_only": {fmtBool(v.Policy.Network.JapanOnly)}, "allow_vpn": {fmtBool(v.Policy.Network.AllowVPN)}, "deny_unresolved": {fmtBool(v.Policy.Network.denyUnresolvedHost())}, "deny_crawlers": {fmtBool(v.Policy.DenyCrawlers)}, "allow_local_ip": {readingSpecialValue(v.Policy.AllowLocalIP)}, "allow_loopback_ip": {readingSpecialValue(v.Policy.AllowLoopbackIP)}}
		for _, kind := range permissionKinds {
			if !slices.Contains(v.Policy.Network.DeniedKinds, kind.Value) {
				fields.Set("allow_"+kind.Value, "true")
			}
		}
	}
	raw, _ := json.Marshal(v.Policy.Network.DeniedCountries)
	codes := h.permissionCountries(url.Values{"denied_countries": {string(raw)}})
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	page := readingPage{State: v, Title: title, Description: description, Action: action, CSRF: s.CSRF("/api/v1" + action), RequestID: fields.Get("request_id"), Peer: peer.Addr().String(), Message: message, Values: fields, Kinds: permissionKinds, Countries: codes}
	if v.Scope != "site" && v.Scope != "admin" {
		page.BoardSettings = "/boards/" + v.Scope + "/settings"
		h.repo.mu.Lock()
		master := h.repo.readingViewLocked("site")
		h.repo.mu.Unlock()
		page.Master = &master
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_ = executeAdminTemplate(w, w, readingTemplate, page)
}
func fmtBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func readingForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	names := []string{"csrf", "revision", "request_id", "allow_local_ip", "allow_loopback_ip", "enabled", "japan_only", "allow_vpn", "deny_unresolved", "deny_crawlers", "allowed_cidrs", "denied_cidrs", "denied_agents", "denied_countries"}
	for _, kind := range permissionKinds {
		names = append(names, "allow_"+kind.Value)
	}
	typ, ok, err := singleRequestHeader(r.Header, "Content-Type")
	media, params, parseErr := mime.ParseMediaType(typ)
	if err != nil || !ok || parseErr != nil || media != "application/x-www-form-urlencoded" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		return nil, ErrPostingRequest
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	fields, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, err
	}
	for _, kind := range permissionKinds {
		name := "allow_" + kind.Value
		if !fields.Has(name) {
			fields.Set(name, "")
		}
	}
	if len(fields) != len(names) {
		return nil, ErrPostingRequest
	}
	for _, name := range names {
		if len(fields[name]) != 1 {
			return nil, ErrPostingRequest
		}
	}
	return fields, nil
}

// readingLines は行単位の空白を除き、IP単独入力を標準CIDRへ変換する。
func readingLines(raw string, cidr bool) ([]string, error) {
	out := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if cidr {
			if addr, err := netip.ParseAddr(line); err == nil {
				addr = addr.Unmap()
				line = netip.PrefixFrom(addr, addr.BitLen()).String()
			}
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				return nil, err
			}
			line = prefix.Masked().String()
		}
		out = append(out, line)
	}
	return out, nil
}
func readingFormPolicy(fields url.Values) (ReadingPolicy, error) {
	p := defaultReadingPolicy()
	for _, name := range []string{"enabled", "japan_only", "allow_vpn", "deny_unresolved", "deny_crawlers"} {
		if value := fields.Get(name); value != "true" && value != "false" {
			return p, errReadingDenied
		}
	}
	for name, dst := range map[string]**bool{"allow_local_ip": &p.AllowLocalIP, "allow_loopback_ip": &p.AllowLoopbackIP} {
		value := fields.Get(name)
		if value == "inherit" {
			continue
		}
		if value != "true" && value != "false" {
			return p, errReadingDenied
		}
		allow := value == "true"
		*dst = &allow
	}
	p.Enabled = fields.Get("enabled") == "true"
	p.Network.JapanOnly = fields.Get("japan_only") == "true"
	p.Network.AllowVPN = fields.Get("allow_vpn") == "true"
	*p.Network.DenyUnresolvedHost = fields.Get("deny_unresolved") == "true"
	p.DenyCrawlers = fields.Get("deny_crawlers") == "true"
	for _, kind := range permissionKinds {
		v := fields.Get("allow_" + kind.Value)
		if v != "" && v != "true" {
			return p, errReadingDenied
		}
		if v == "" {
			p.Network.DeniedKinds = append(p.Network.DeniedKinds, kind.Value)
		}
	}
	var err error
	p.AllowedCIDRs, err = readingLines(fields.Get("allowed_cidrs"), true)
	if err != nil {
		return p, err
	}
	p.DeniedCIDRs, err = readingLines(fields.Get("denied_cidrs"), true)
	if err != nil {
		return p, err
	}
	p.DeniedAgents, err = readingLines(fields.Get("denied_agents"), false)
	if err != nil {
		return p, err
	}
	p.Network.DeniedCountries, err = readingLines(strings.ToUpper(fields.Get("denied_countries")), false)
	if err != nil {
		return p, err
	}
	_, err = compileReadingPolicy(p)
	return p, err
}

// readingSpecialValue は旧設定の未指定を従来の回線条件として表示する。
func readingSpecialValue(v *bool) string {
	if v == nil {
		return "inherit"
	}
	return fmtBool(*v)
}
