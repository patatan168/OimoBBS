// 管理専用のloopback HTTPまたは直結HTTPS。認証・Origin・CSRFとクローラー拒否を適用する。
package bootstrap

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/delivery"
	"oimobbs/internal/domain"
	"oimobbs/internal/securityaudit"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// AdminHTTPServer は明示起動する管理サーバーを作る。Listen/Shutdownは呼出元の責務。
func (r *Repository) AdminHTTPServer() (*http.Server, error) {
	if e := r.cfg.validate(); e != nil {
		return nil, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return nil, e
	}
	accounts, e := r.administrators()
	if e != nil {
		return nil, e
	}
	if len(accounts) == 0 {
		return nil, errors.New("initialize an administrator before enabling admin listener")
	}
	if r.adminAuth == nil {
		r.adminAuth, e = adminauth.New()
		if e != nil {
			return nil, e
		}
	}
	gate, e := delivery.NewRequestGate(32, 32)
	if e != nil {
		return nil, e
	}
	if r.egress == nil {
		r.egress, e = delivery.New(r.operations().EgressBits)
		if e != nil {
			return nil, e
		}
	}
	origin, _, _ := r.cfg.adminEndpoint()
	audit, e := securityaudit.New(os.Stderr)
	if e != nil {
		return nil, e
	}
	handler := &adminHandler{repo: r, auth: r.adminAuth, origin: origin.String(), security: audit}
	server := &http.Server{Addr: r.cfg.Admin.Listen, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	if r.cfg.Admin.Transport == "direct_https" {
		if _, e := r.cfg.loadAdminTLSCertificate(time.Now()); e != nil {
			return nil, e
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return r.cfg.loadAdminTLSCertificate(time.Now()) }}
		server.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 16, MaxReadFrameSize: 16 << 10, MaxReceiveBufferPerConnection: 256 << 10, MaxReceiveBufferPerStream: 64 << 10, WriteByteTimeout: 10 * time.Second}
	}
	server.RegisterOnShutdown(gate.Close)
	var routes http.Handler = handler
	if r.cfg.Admin.Transport == "public_path" {
		_, base, _ := r.cfg.adminEndpoint()
		routes = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			mounted := &adminMountResponse{ResponseWriter: w, base: base}
			if !canonicalRequestPath(req) || !(req.URL.Path == base || strings.HasPrefix(req.URL.Path, base+"/")) {
				handler.fail(mounted, req, 403, "REQUEST_REJECTED")
				return
			}
			cloned := req.Clone(req.Context())
			u := *req.URL
			u.Path = strings.TrimPrefix(u.Path, base)
			if u.Path == "" {
				u.Path = "/"
			}
			u.RawPath = ""
			cloned.URL = &u
			handler.ServeHTTP(mounted, cloned)
		})
	}
	bounded := r.trafficHandler(r.egress.Wrap(gate.Wrap(r.wafHandler(routes))), true)
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		adminResponseHeaders(w)
		bounded.ServeHTTP(w, req)
	})
	server.Handler = securityTransportHeaders(server.Handler)
	return server, nil
}

// adminResponseHeaders は認証前の拒否や過負荷応答にも巡回・埋込み・参照元送信の抑止を適用する。
func adminResponseHeaders(w http.ResponseWriter) {
	postingHeaders(w)
	// 管理画面の回線分類更新等のfetchは、同じOriginに限って許可する。
	w.Header().Set("Content-Security-Policy", w.Header().Get("Content-Security-Policy")+"; connect-src 'self'")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
	// no-referrerではブラウザのフォームPOSTがOrigin:nullになり、同一Origin検査で拒否される。
	// 同じ管理Originへの送信だけ発行元を保持し、外部への参照元送信は抑止する。
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
}

type adminHandler struct {
	repo     *Repository
	auth     *adminauth.Manager
	origin   string
	security *securityaudit.Logger
}

func (h *adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	navigation := &adminMountResponse{ResponseWriter: w, menu: map[string]bool{}}
	w = navigation
	adminResponseHeaders(w)
	if !canonicalRequestPath(r) || !localAdminBrowser(r) {
		h.fail(w, r, 403, "REQUEST_REJECTED")
		return
	}
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	ip, err := netip.ParseAddr(host)
	configured, _ := parseOrigin(h.origin)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	requested, e2 := parseOrigin(scheme + "://" + r.Host)
	transportOK := h.repo.cfg.Admin.Transport == "direct_https" && r.TLS != nil || h.repo.cfg.Admin.Transport == "loopback_tunnel" && ip.Unmap().IsLoopback() && r.TLS == nil
	if h.repo.cfg.Admin.Transport == "public_path" {
		transportOK = configured.Scheme == "https" && r.TLS != nil || configured.Scheme == "http" && r.TLS == nil && ip.Unmap().IsLoopback()
	}
	if e != nil || err != nil || !transportOK || e2 != nil || normalizedOrigin(configured) != normalizedOrigin(requested) || r.URL.EscapedPath() != r.URL.Path || (r.URL.RawQuery != "" && !validReauthQuery(r) && !(r.Method == "GET" && (r.URL.Path == "/reports" || r.URL.Path == "/api/v1/reports") && validReportQuery(r.URL.RawQuery)) && !(r.Method == "GET" && (adminListRoute(r.URL.Path) || r.URL.Path == "/audit" || r.URL.Path == "/api/v1/audit" || strings.HasPrefix(r.URL.Path, "/boards/") && strings.HasSuffix(r.URL.Path, "/threads")))) {
		h.fail(w, r, 403, "REQUEST_REJECTED")
		return
	}
	var readingDenied bool
	w, readingDenied = h.repo.readingGate(w, r, "admin")
	if readingDenied {
		return
	}
	if r.Method == "GET" && r.URL.Path == "/robots.txt" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "User-agent: *\nDisallow: /\n")
		return
	}
	if knownContentCrawler(r.UserAgent()) {
		h.fail(w, r, 403, "REQUEST_REJECTED")
		return
	}
	if webui.ServeAsset(w, r) {
		return
	}
	if r.Method != "GET" && r.Method != "POST" && r.Method != "PATCH" {
		w.Header().Set("Allow", "GET, POST, PATCH")
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if r.Method != "GET" && !h.sameOrigin(r) {
		h.fail(w, r, 403, "ORIGIN_REJECTED")
		return
	}
	if r.URL.Path == "/login" {
		if r.Method == "GET" {
			h.loginPage(w, 200, "")
			return
		}
		if r.Method == "POST" {
			h.login(w, r, ip.Unmap().String())
			return
		}
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	raw, e := singlePostingCookie(r.Header, "oimo_admin", 43)
	if e != nil {
		h.fail(w, r, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	session, e := h.auth.Lookup(raw, time.Now())
	if e != nil {
		if r.Method == "GET" && r.URL.Path == "/" {
			http.Redirect(w, r, "/login", 303)
			return
		}
		h.fail(w, r, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	h.repo.mu.Lock()
	account, e := h.repo.currentAdminSession(session)
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	navigation.menu = adminNavigation(account)
	if e := h.authorizeRoute(session, r); e != nil {
		h.failure(w, r, e)
		return
	}
	switch {
	case r.URL.Path == "/manual":
		h.manual(w, r)
	case r.URL.Path == "/abuse-guard" || r.URL.Path == "/api/v1/abuse-guard":
		h.abuseGuardRoutes(w, r, session)
	case isReadingRoute(r.URL.Path):
		h.readingRoutes(w, r, session)
	case r.URL.Path == "/waf" || r.URL.Path == "/api/v1/waf":
		h.wafRoutes(w, r, session)
	case r.URL.Path == "/operations" || r.URL.Path == "/api/v1/operations":
		h.operationsRoutes(w, r, session)
	case r.URL.Path == "/auto-reports" || strings.HasPrefix(r.URL.Path, "/auto-reports/"):
		h.autoReportRoutes(w, r, session)
	case strings.TrimPrefix(r.URL.Path, "/api/v1") == "/reports" || strings.HasPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1"), "/reports/"):
		h.reportRoutes(w, r, session)
	case strings.TrimPrefix(r.URL.Path, "/api/v1") == "/evidence" || strings.HasPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1"), "/evidence/"):
		h.evidenceRoutes(w, r, session)
	case strings.TrimPrefix(r.URL.Path, "/api/v1") == "/caps" || strings.HasPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1"), "/caps/"):
		h.capsRoutes(w, r, session)
	case r.URL.Path == "/anonymous" || r.URL.Path == "/api/v1/anonymous":
		h.anonymousRoutes(w, r, session)
	case strings.TrimPrefix(r.URL.Path, "/api/v1") == "/administrators" || strings.HasPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1"), "/administrators/"):
		h.accountsRoutes(w, r, session)
	case r.URL.Path == "/reauth" || r.URL.Path == "/api/v1/reauth":
		h.reauthenticate(w, r, raw, session, ip.Unmap().String())
	case r.URL.Path == "/maintenance/emergency-reserve" || r.URL.Path == emergencyReserveRoute:
		h.emergencyReserveRoutes(w, r, session)
	case r.Method == "GET" && (r.URL.Path == "/maintenance" || r.URL.Path == "/api/v1/maintenance"):
		status := h.repo.MaintenanceStatus()
		capacity := h.repo.PostingCapacity()
		latency := h.repo.PostingLatency()
		deliveryStatus := h.repo.DeliveryStatus()
		compression := h.repo.feedCompression.Status()
		optionalLogs := h.repo.OptionalHTTPLogs()
		if r.URL.Path == "/api/v1/maintenance" {
			w.Header().Set("X-CSRF-Token", session.CSRF(emergencyReserveRoute))
			adminJSON(w, 200, map[string]any{"data": status, "posting_capacity": capacity, "posting_latency": latency, "delivery": deliveryStatus, "feed_compression": compression, "optional_http_logs": optionalLogs})
			return
		}
		writeAdminPage(w, 200, adminPage{Title: "保存の自動整理", CSRF: session.CSRF(emergencyReserveRoute), Maintenance: &status, Capacity: &capacity, Latency: &latency, Delivery: &deliveryStatus, Compression: &compression, OptionalLogs: &optionalLogs})
	case r.URL.Path == "/board-categories":
		h.categoriesRoutes(w, r, session)
	case r.URL.Path == "/networks" || strings.HasPrefix(r.URL.Path, "/api/v1/networks"):
		h.networksRoutes(w, r, session)
	case r.URL.Path == "/audit" || r.URL.Path == "/api/v1/audit":
		h.audit(w, r, session)
	case r.URL.Path == "/boards" || r.URL.Path == "/api/v1/boards":
		h.boards(w, r, session)
	case strings.HasPrefix(r.URL.Path, "/boards/") || strings.HasPrefix(r.URL.Path, "/api/v1/boards/"):
		h.boardSettings(w, r, session)
	case r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/api/v1/site"):
		site, e := h.repo.adminSite(session)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", site.ETag())
		if r.URL.Path == "/api/v1/site" {
			w.Header().Set("X-CSRF-Token", session.CSRF("/api/v1/site"))
			adminJSON(w, 200, map[string]any{"data": site, "revision": site.Revision, "request_id": domain.NewID()})
			return
		}
		h.settingsPage(w, site, session)
	case r.Method == "POST" && r.URL.Path == "/logout":
		fields, e := adminForm(w, r, 8<<10, "csrf")
		if e != nil || !session.CheckCSRF("/logout", fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		h.auth.Delete(raw)
		h.security.Record("logout", "success", ip.Unmap().String(), session.Admin.String(), time.Now())
		http.SetCookie(w, h.adminCookie("oimo_admin", "", -1))
		http.Redirect(w, r, "/login", 303)
	case r.Method == "POST" && r.URL.Path == "/site", r.Method == "PATCH" && r.URL.Path == "/api/v1/site":
		h.update(w, r, session)
	default:
		h.fail(w, r, 404, "NOT_FOUND")
	}
}
func (h *adminHandler) sameOrigin(r *http.Request) bool {
	origin, present, e := singleRequestHeader(r.Header, "Origin")
	if e != nil {
		return false
	}
	if !present {
		ref, ok, e := singleRequestHeader(r.Header, "Referer")
		if e != nil || !ok {
			return false
		}
		u, e := url.Parse(ref)
		if e != nil || u.User != nil || u.Opaque != "" || u.Fragment != "" {
			return false
		}
		origin = u.Scheme + "://" + u.Host
	}
	u, e := parseOrigin(origin)
	if e != nil {
		return false
	}
	want, _ := parseOrigin(h.origin)
	return normalizedOrigin(u) == normalizedOrigin(want)
}

// adminCookie は管理HTTPSではSecureを付け、ログイン・セッション・失効を同じ属性で発行する。
func (h *adminHandler) adminCookie(name, value string, age int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: h.cookiePath(), HttpOnly: true, Secure: strings.HasPrefix(h.origin, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: age}
}
func adminForm(w http.ResponseWriter, r *http.Request, limit int64, names ...string) (url.Values, error) {
	value, ok, e := singleRequestHeader(r.Header, "Content-Type")
	if e != nil || !ok {
		return nil, ErrPostingRequest
	}
	media, params, e := mime.ParseMediaType(value)
	if e != nil || media != "application/x-www-form-urlencoded" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		return nil, ErrPostingRequest
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if e != nil {
		return nil, e
	}
	fields, e := url.ParseQuery(string(raw))
	// 板の種類がなかった従来の追加フォームは通常板として扱う。
	if e == nil && slices.Contains(names, "posting_mode") && !fields.Has("posting_mode") {
		fields.Set("posting_mode", "anyone")
	}
	if e == nil && slices.Contains(names, "require_id") {
		e = normalizeIDSelection(fields)
	}
	if e == nil && slices.Contains(names, "slip_mode") {
		e = normalizeDisplaySelection(fields, slices.Contains(names, "require_slip_hash"))
	}
	if e == nil && slices.Contains(names, "board_ids") {
		e = normalizeBoardSelection(fields)
	}
	if e == nil && slices.Contains(names, "extra_permissions") {
		e = normalizePermissionSelection(fields, "extra_permissions")
	}
	if e == nil && slices.Contains(names, "permissions") {
		e = normalizePermissionSelection(fields, "permissions")
	}
	if e != nil || len(fields) != len(names) {
		return nil, ErrPostingRequest
	}
	for _, name := range names {
		if len(fields[name]) != 1 {
			return nil, ErrPostingRequest
		}
	}
	return fields, nil
}
func (h *adminHandler) login(w http.ResponseWriter, r *http.Request, ip string) {
	outcome, accountID := "rejected", ""
	defer func() { h.security.Record("login", outcome, ip, accountID, time.Now()) }()
	fields, e := adminForm(w, r, 8<<10, "login", "password", "csrf")
	if e != nil || !adminLoginName.MatchString(fields.Get("login")) || len(fields.Get("password")) > 512 {
		h.fail(w, r, 400, "INVALID_LOGIN_FORM")
		return
	}
	raw, e := singlePostingCookie(r.Header, "oimo_admin_login", 43)
	if e != nil || h.auth.ConsumeLogin(raw, fields.Get("csrf"), time.Now()) != nil {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	if e = h.auth.Attempt(ip, fields.Get("login"), time.Now()); e != nil {
		outcome = authenticationOutcome(e)
		h.failure(w, r, e)
		return
	}
	h.repo.mu.Lock()
	available := h.repo.available()
	accounts, err := h.repo.administrators()
	h.repo.mu.Unlock()
	if available != nil || err != nil {
		outcome = "error"
		h.fail(w, r, 503, "UNAVAILABLE")
		return
	}
	var selected *administrator
	for _, a := range accounts {
		if a.Login == fields.Get("login") && a.Enabled {
			copy := a
			selected = &copy
			break
		}
	}
	var password *adminauth.Password
	if selected != nil {
		password = &selected.Password
	}
	valid, e := h.auth.Verify(r.Context(), password, fields.Get("password"))
	if e != nil {
		outcome = authenticationOutcome(e)
		h.failure(w, r, e)
		return
	}
	if !valid {
		outcome = "failed"
		h.loginPage(w, 401, "ログイン名またはパスワードを確認してください。")
		return
	}
	h.repo.mu.Lock()
	_, e = h.repo.currentAdminAccount(adminauth.Session{Admin: selected.ID, Generation: selected.Generation})
	var cookie string
	if e == nil {
		cookie, _, e = h.auth.Create(selected.ID, selected.Generation, time.Now())
	}
	h.repo.mu.Unlock()
	if e != nil {
		outcome = "error"
		h.failure(w, r, e)
		return
	}
	if old, e := singlePostingCookie(r.Header, "oimo_admin", 43); e == nil {
		h.auth.Delete(old)
	}
	http.SetCookie(w, h.adminCookie("oimo_admin", cookie, 8*3600))
	outcome, accountID = "success", selected.ID.String()
	http.SetCookie(w, h.adminCookie("oimo_admin_login", "", -1))
	landing := "/auto-reports"
	if selected.Role == "board_admin" {
		landing = "/boards"
	}
	if selected.Role == "site_admin" {
		landing = "/"
	}
	http.Redirect(w, r, landing, 303)
}
func (h *adminHandler) update(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	var name, etag, key, csrf string
	if r.URL.Path == "/site" {
		fields, e := adminForm(w, r, 256<<10, "name", "revision", "request_id", "csrf")
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		name, etag, key, csrf = fields.Get("name"), fields.Get("revision"), fields.Get("request_id"), fields.Get("csrf")
	} else {
		var e error
		csrf, _, e = singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil {
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
		value, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, _, err := mime.ParseMediaType(value)
		if e != nil || err != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		if !s.CheckCSRF("/api/v1/site", csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
		var input struct {
			Name string `json:"name"`
		}
		if e != nil || strictjson.Decode(raw, &input) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		name = input.Name
	}
	if !s.CheckCSRF("/api/v1/site", csrf) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	site, e := h.repo.updateAdminSite(s, name, etag, key)
	if e != nil {
		if r.URL.Path == "/site" && !errors.Is(e, adminauth.ErrSession) {
			status := 503
			message := "結果を確認できません。同じ入力・要求IDで確認してください。"
			var f *adminFailure
			if errors.As(e, &f) {
				status = f.status
				if f.operation != (domain.ID{}) {
					w.Header().Set("X-Operation-ID", f.operation.String())
				}
			}
			if status == 412 {
				message = "別の変更が保存されています。入力内容を控えて、最新の設定を読み直してください。"
			}
			if status == 400 || status == 422 {
				message = "入力内容を確認してください。"
			}
			if status == 409 {
				message = "この要求IDは別の変更に使用済みです。設定を開き直してください。"
			}
			writeAdminPage(w, status, adminPage{Title: "設定を保存できません", Message: message, Settings: true, Name: name, ETag: etag, RequestID: key, CSRF: csrf, LogoutCSRF: s.CSRF("/logout")})
		} else {
			h.failure(w, r, e)
		}
		return
	}
	if r.URL.Path == "/site" {
		http.Redirect(w, r, "/", 303)
		return
	}
	w.Header().Set("ETag", site.ETag())
	adminJSON(w, 200, map[string]any{"data": site, "revision": site.Revision, "request_id": domain.NewID()})
}
func adminJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (h *adminHandler) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		adminJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": "操作を完了できませんでした。認証・入力・最新の設定を確認してください。"}, "request_id": domain.NewID()})
		return
	}
	message := "操作を完了できませんでした。入力とログイン状態を確認してください。"
	backPath := ""
	actionLabel := ""
	if code == "REAUTHENTICATION_REQUIRED" {
		message = "パスワードの再認証が必要です。完了すると元の管理画面へ戻ります。"
		backPath = "/reauth?" + url.Values{"return_to": {adminReturnPath(r.URL.Path)}}.Encode()
		actionLabel = "パスワードを再認証して続ける"
		if r.Method == "GET" {
			http.Redirect(w, r, backPath, 303)
			return
		}
	}
	if code == "REAUTHENTICATION_REQUIRED" && strings.HasPrefix(r.URL.Path, "/auto-reports/") {
		parent := strings.TrimSuffix(strings.TrimSuffix(r.URL.Path, "/inspect"), "/rule")
		backPath = "/reauth?" + url.Values{"return_to": {adminReturnPath(parent)}}.Encode()
	}
	if status == 412 {
		message = "別の変更が保存されています。設定を読み直して編集してください。"
	}
	if status == 503 {
		message = "結果を確認できません。同じ要求IDで確認してください。"
	}
	if code == "EVIDENCE_PERMISSION_REQUIRED" {
		message = "提出用ログの操作に必要な追加権限がありません。サイト管理者に権限の設定を依頼してください。"
	}
	if code == "PRIVATE_REPORT_PERMISSION_REQUIRED" {
		message = "削除依頼・照会の閲覧と回答には「削除依頼の閲覧・回答」の追加権限が必要です。サイト管理者に権限の設定を依頼してください。"
	}
	if strings.TrimPrefix(r.URL.Path, "/api/v1") == "/maintenance/emergency-reserve" {
		message = "復旧用予約を確保できませんでした。状態と空き容量を確認してから再試行してください。"
		if code == "RESERVE_CAPACITY_UNAVAILABLE" {
			message = "復旧用予約を確保する空き容量が不足しているか、容量を確認できません。保存領域を整理してから再試行してください。"
		}
		backPath, actionLabel = "/maintenance", "保存の整理へ戻って確認する"
	}
	if code == "CLEANUP_PENDING" {
		message = "保存掃除はまだ完了していません。保存容量とコピー別の状態を確認してから再試行してください。"
		backPath = strings.TrimSuffix(r.URL.Path, "/cleanup")
	}
	if strings.HasPrefix(r.URL.Path, "/evidence/") && code != "REAUTHENTICATION_REQUIRED" {
		if explanation := evidenceFailureMessage(code); explanation != "" {
			message = explanation
		}
		backPath = "/evidence"
		actionLabel = "提出用ログへ戻って確認する"
	}
	if owner, key, parts, ok := adminPostsPath(r.URL.Path); ok {
		parent := fmt.Sprintf("/boards/%s/threads/%d/posts/1", owner, key)
		if len(parts) > 4 {
			if n, e := strconv.ParseUint(parts[4], 10, 32); e == nil && n > 0 {
				parent = fmt.Sprintf("/boards/%s/threads/%d/posts/%d", owner, key, (n-1)/50*50+1)
			}
		}
		if code == "REAUTHENTICATION_REQUIRED" {
			backPath = "/reauth?" + url.Values{"return_to": {parent}}.Encode()
		} else {
			backPath = parent
			actionLabel = "レスの管理画面へ戻る"
		}
		switch code {
		case "EVIDENCE_IDENTITY_UNAVAILABLE":
			message = "このレスには選んだIP・匿名主体の記録がありません。このレスだけを選択してください。"
		case "INVALID_RESPONSE_NUMBER":
			message = "レス番号を1以上の整数で入力してください。"
		case "EVIDENCE_SCOPE_LIMIT":
			message = "同じIP・内部IDの記録が100件または8MiBの上限を超えています。このレスだけを選択してください。"
		case "POST_EVIDENCE_NOT_FOUND":
			message = "このレスの受理記録は見つからないか、保持期限が終了しています。自動追加レスには投稿者の記録はありません。"
		case "RULE_TARGET_NOT_RECORDED":
			message = "選んだ項目を記録から取得できません。ホストは逆引きと投稿元IPの対応を確認できた場合だけ使用できます。IPなど別の項目を選んでください。"
		case "EVIDENCE_SELECTION_CHANGED":
			message = "表示後に選択範囲が更新されました。記録を再表示してからZIPを取得してください。"
		default:
			if explanation := evidenceFailureMessage(code); explanation != "" {
				message = explanation
			}
		}
	}

	writeAdminPage(w, status, adminPage{Title: "管理操作を完了できません", Message: message, BackPath: backPath, ActionPath: backPath, ActionLabel: actionLabel})
}
func (h *adminHandler) failure(w http.ResponseWriter, r *http.Request, e error) {
	var f *adminFailure
	if errors.As(e, &f) {
		if f.operation != (domain.ID{}) {
			w.Header().Set("X-Operation-ID", f.operation.String())
		}
		h.fail(w, r, f.status, f.code)
		return
	}
	var limited *adminauth.Limited
	if errors.As(e, &limited) {
		w.Header().Set("Retry-After", strconv.FormatUint(limited.RetryAfter, 10))
		h.fail(w, r, 429, "LOGIN_RATE_EXCEEDED")
		return
	}
	if errors.Is(e, adminauth.ErrSession) {
		h.fail(w, r, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	h.fail(w, r, 503, "UNAVAILABLE")
}

// cookiePath は管理Cookieを隠しパス配下に限定し、公開ページには送らせない。
func (h *adminHandler) cookiePath() string {
	_, base, _ := h.repo.cfg.adminEndpoint()
	return base + "/"
}
