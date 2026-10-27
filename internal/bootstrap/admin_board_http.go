// 板設定の管理APIとHTMLを、同じ認可・CSRF・CAS・保存処理へ接続する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"strconv"
	"strings"
	"time"
)

func (h *adminHandler) boards(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if r.Method == "POST" && r.URL.Path == "/boards" {
		h.createBoard(w, r, s)
		return
	}
	if r.Method != "GET" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if r.URL.Path == "/boards" && r.URL.RawQuery == "" && renderAdminAssetOnly(w, r, adminBoardsTemplate, adminBoardsPage{}) {
		return
	}
	_, boards, e := h.repo.webBoards()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	rows := make([]AdminBoard, 0, len(boards))
	for _, b := range boards {
		h.repo.mu.Lock()
		allowed := h.repo.authorizeAdmin(s, "board_admin", b.ID)
		h.repo.mu.Unlock()
		if allowed != nil {
			continue
		}
		row, e := h.repo.adminBoardSettings(r.Context(), s, b.ID)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		rows = append(rows, row)
	}
	keys := make([]string, len(rows))
	for i, row := range rows {
		keys[i] = row.ID.String()
	}
	revision, err := adminListRevision(rows)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	window, err := adminListSlice(r, s, revision, keys, time.Now())
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if r.URL.Path == "/api/v1/boards" {
		adminJSON(w, 200, listMetadata(rows[window.Start:window.End], window, revision))
		return
	}
	h.repo.mu.Lock()
	canCreate := h.repo.authorizeAdmin(s, "site_admin", domain.ID{}) == nil
	h.repo.mu.Unlock()
	writeAdminBoards(w, 200, adminBoardsPage{Rows: rows[window.Start:window.End], Next: adminNextLink(r.URL.Path, window), CanCreate: canCreate, CreateReady: s.Reauthenticated(time.Now()), PublicURL: strings.TrimRight(h.repo.cfg.Public.BaseURL, "/"), Values: url.Values{"csrf": {s.CSRF("/boards")}}})
	return
}
func (h *adminHandler) boardSettings(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if _, _, _, ok := adminPostsPath(r.URL.Path); ok {
		h.adminPosts(w, r, s)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/threads") {
		h.moderationThreads(w, r, s)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/actions") {
		h.threadActionRoutes(w, r, s)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/moderation") || strings.HasSuffix(r.URL.Path, "/moderation/cleanup") {
		h.moderation(w, r, s)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/local-rules") {
		h.localRules(w, r, s)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/thread-settings") {
		h.threadSettings(w, r, s)
		return
	}
	if strings.Contains(r.URL.Path, "/rules") {
		h.ruleRoutes(w, r, s)
		return
	}
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	prefix := "/boards/"
	if api {
		prefix = "/api/v1/boards/"
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	var id domain.ID
	if len(parts) != 2 || parts[1] != "settings" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &id) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	route := "/api/v1/boards/" + id.String() + "/settings"
	action := "/boards/" + id.String() + "/settings"
	if r.Method == "GET" {
		b, e := h.repo.adminBoardSettings(r.Context(), s, id)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", b.ETag())
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]any{"data": b, "revision": b.Revision, "request_id": domain.NewID()})
		} else {
			fields := adminBoardFields(b.Settings)
			access := b.Settings.identitySettings().Access
			if access != nil {
				for key, values := range map[string][]string{"denied_kinds": access.DeniedKinds, "denied_countries": access.DeniedCountries} {
					raw, _ := json.Marshal(values)
					fields.Set(key, string(raw))
				}
			}
			fields.Set("revision", b.ETag())
			fields.Set("request_id", domain.NewID().String())
			fields.Set("csrf", s.CSRF(route))
			writeAdminBoards(w, 200, adminBoardsPage{Editing: true, Name: b.Name, Action: action, ThreadAction: "/boards/" + id.String() + "/thread-settings", ModerationAction: "/boards/" + id.String() + "/threads", PublicURL: strings.TrimRight(h.repo.cfg.Public.BaseURL, "/"), BoardKey: b.Key, CountryCodes: h.permissionCountries(fields), Values: fields})
		}
		return
	}
	if api && r.Method != "PATCH" || !api && r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var edit AdminBoardEdit
	var fields url.Values
	var etag, key string
	var e error
	if api {
		csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
		if err != nil || !s.CheckCSRF(route, csrf) {
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
		content, _, err := singleRequestHeader(r.Header, "Content-Type")
		media, params, err2 := mime.ParseMediaType(content)
		if err != nil || err2 != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
		if err != nil {
			h.fail(w, r, 413, "BODY_TOO_LARGE")
			return
		}
		if strictjson.Decode(raw, &edit) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		fields, e = readBoardPermissionForm(w, r)
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF(route, fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, key = fields.Get("revision"), fields.Get("request_id")
		edit, e = parseAdminBoardFields(fields)
	}
	var result AdminBoard
	if e == nil {
		result, e = h.repo.updateAdminBoard(r.Context(), s, id, edit, etag, key)
	}
	if e != nil {
		if api || errors.Is(e, adminauth.ErrSession) {
			h.failure(w, r, e)
			return
		}
		status, message := 503, "結果を確認できません。同じ入力・要求IDで確認してください。"
		var f *adminFailure
		if errors.As(e, &f) {
			status = f.status
			if f.operation != (domain.ID{}) {
				w.Header().Set("X-Operation-ID", f.operation.String())
			}
		}
		switch status {
		case 400, 422:
			message = "入力を確認してください。名前のバイト上限には名無し名も収め、名前必須と強制名無しは同時に指定できません。"
		case 412:
			message = "別の変更が保存されています。入力内容を控え、最新の設定を読み直してください。"
		case 409:
			message = "要求IDが別の変更に使われています。最新の設定を読み直してください。"
		}
		if f != nil && f.code == "ANONYMOUS_NOT_ENABLED" {
			message = "匿名Cookie機能を有効化できませんでした。入力内容は保持しています。"
		}
		writeAdminBoards(w, status, adminBoardsPage{Editing: true, Action: action, ThreadAction: "/boards/" + id.String() + "/thread-settings", ModerationAction: "/boards/" + id.String() + "/threads", CountryCodes: h.permissionCountries(fields), Values: fields, Message: message})
		return
	}
	if !api {
		http.Redirect(w, r, action, 303)
		return
	}
	w.Header().Set("ETag", result.ETag())
	adminJSON(w, 200, map[string]any{"data": result, "revision": result.Revision, "request_id": domain.NewID()})
}

var adminBoardFieldNames = []string{"name_bytes", "mail_bytes", "title_bytes", "body_bytes", "body_lines", "noname", "name_required", "force_noname", "hide_mail", "create_policy", "reply_policy", "cookie_mode", "token_wait_seconds", "revision", "request_id", "csrf", "rate_enabled", "reply_seconds", "reply_burst", "create_seconds", "create_burst", "create_window_limit", "id_mode", "slip_mode", "require_public_ip", "allow_thread_strengthen", "display_commands", "network_classes", "japan_only", "allow_vpn", "no_reprint", "hidden", "auto_reports_enabled"}

func adminBoardFields(s AdminBoardEdit) url.Values {
	i := s.Input
	fields := url.Values{"name_bytes": {strconv.FormatUint(uint64(i.NameBytes), 10)}, "mail_bytes": {strconv.FormatUint(uint64(i.MailBytes), 10)}, "title_bytes": {strconv.FormatUint(uint64(i.TitleBytes), 10)}, "body_bytes": {strconv.FormatUint(uint64(i.BodyBytes), 10)}, "body_lines": {strconv.FormatUint(uint64(i.BodyLines), 10)}, "noname": {i.Noname}, "name_required": {strconv.FormatBool(i.NameRequired)}, "force_noname": {strconv.FormatBool(i.ForceNoname)}, "hide_mail": {strconv.FormatBool(i.HideMail)}, "create_policy": {s.Create}, "reply_policy": {s.Reply}, "cookie_mode": {s.anonymous().Mode}, "token_wait_seconds": {strconv.FormatUint(uint64(s.anonymous().Wait), 10)}}
	fields.Set("auto_reports_enabled", strconv.FormatBool(s.AutoReportsEnabled == nil || *s.AutoReportsEnabled))
	fields.Set("hidden", strconv.FormatBool(s.Hidden != nil && *s.Hidden))
	fields.Set("no_reprint", strconv.FormatBool(s.NoReprint != nil && *s.NoReprint))
	rates := s.rates()
	if s.Rates == nil {
		rates.Enabled = false
	}
	fields.Set("rate_enabled", strconv.FormatBool(rates.Enabled))
	for key, value := range map[string]uint32{"reply_seconds": rates.ReplySeconds, "reply_burst": rates.ReplyBurst, "create_seconds": rates.CreateSeconds, "create_burst": rates.CreateBurst, "create_window_limit": rates.CreateWindow} {
		fields.Set(key, strconv.FormatUint(uint64(value), 10))
	}
	ident := s.identitySettings()
	access := NetworkAccessSettings{AllowVPN: true}
	if ident.Access != nil {
		access = *ident.Access
	}
	fields.Set("japan_only", strconv.FormatBool(access.JapanOnly))
	fields.Set("allow_vpn", strconv.FormatBool(access.AllowVPN))
	fields.Set("deny_unresolved_host", strconv.FormatBool(access.denyUnresolvedHost()))
	fields.Set("id_mode", ident.IDMode)
	fields.Set("slip_mode", ident.SlipMode)
	fields.Set("require_public_ip", strconv.FormatBool(ident.RequireIP))
	fields.Set("allow_thread_strengthen", strconv.FormatBool(ident.AllowStrengthen))
	commands, _ := json.Marshal(ident.DisplayCommands)
	fields.Set("display_commands", string(commands))
	raw, _ := json.Marshal(ident.Networks)
	fields.Set("network_classes", string(raw))
	return fields
}
func parseAdminBoardFields(v url.Values) (AdminBoardEdit, error) {
	s := AdminBoardEdit{Create: v.Get("create_policy"), Reply: v.Get("reply_policy")}
	if v.Has("auto_reports_enabled") && v.Get("auto_reports_enabled") != "null" {
		value := v.Get("auto_reports_enabled")
		if value != "true" && value != "false" {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		on := value == "true"
		s.AutoReportsEnabled = &on
	}
	if v.Has("hidden") && v.Get("hidden") != "null" {
		value := v.Get("hidden")
		if value != "true" && value != "false" {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		on := value == "true"
		s.Hidden = &on
	}
	if v.Has("no_reprint") && v.Get("no_reprint") != "null" {
		value := v.Get("no_reprint")
		if value != "true" && value != "false" {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		on := value == "true"
		s.NoReprint = &on
	}
	numbers := []*uint32{&s.Input.NameBytes, &s.Input.MailBytes, &s.Input.TitleBytes, &s.Input.BodyBytes, &s.Input.BodyLines}
	for i, p := range numbers {
		raw := v.Get(adminBoardFieldNames[i])
		n, e := strconv.ParseUint(raw, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != raw {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		*p = uint32(n)
	}
	mode, wait := v.Get("cookie_mode"), v.Get("token_wait_seconds")
	if mode != "" || wait != "" {
		n, e := strconv.ParseUint(wait, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != wait {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		s.Anonymous = &AdminAnonymousSettings{mode, uint32(n)}
	}

	if v.Has("rate_enabled") {
		rates := defaultRateSettings()
		switch v.Get("rate_enabled") {
		case "true":
			rates.Enabled = true
		case "false":
			rates.Enabled = false
		default:
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		for key, p := range map[string]*uint32{"reply_seconds": &rates.ReplySeconds, "reply_burst": &rates.ReplyBurst, "create_seconds": &rates.CreateSeconds, "create_burst": &rates.CreateBurst, "create_window_limit": &rates.CreateWindow} {
			raw := v.Get(key)
			n, e := strconv.ParseUint(raw, 10, 32)
			if e != nil || strconv.FormatUint(n, 10) != raw {
				return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
			}
			*p = uint32(n)
		}
		s.Rates = &rates
	}
	if v.Has("slip_mode") {
		ident := AdminIdentitySettings{IDMode: v.Get("id_mode"), SlipMode: v.Get("slip_mode")}
		for key, target := range map[string]*bool{"require_public_ip": &ident.RequireIP, "allow_thread_strengthen": &ident.AllowStrengthen} {
			value := v.Get(key)
			if value != "true" && value != "false" {
				return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
			}
			*target = value == "true"
		}
		if json.Unmarshal([]byte(v.Get("display_commands")), &ident.DisplayCommands) != nil {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		if decodeNetworkClasses(v.Get("network_classes"), &ident.Networks) != nil || ident.validate() != nil {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		if v.Has("japan_only") || v.Has("allow_vpn") {
			access := NetworkAccessSettings{}
			for key, target := range map[string]*bool{"japan_only": &access.JapanOnly, "allow_vpn": &access.AllowVPN} {
				value := v.Get(key)
				if value != "true" && value != "false" {
					return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
				}
				*target = value == "true"
			}
			if v.Has("denied_kinds") {
				if json.Unmarshal([]byte(v.Get("denied_kinds")), &access.DeniedKinds) != nil || json.Unmarshal([]byte(v.Get("denied_countries")), &access.DeniedCountries) != nil || access.validate() != nil {
					return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
				}
			}
			if v.Has("deny_unresolved_host") {
				value := v.Get("deny_unresolved_host")
				if value != "true" && value != "false" {
					return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
				}
				deny := value == "true"
				access.DenyUnresolvedHost = &deny
			}
			ident.Access = &access
		}
		s.Identity = &ident
	}
	s.Input.Noname = v.Get("noname")
	for name, p := range map[string]*bool{"name_required": &s.Input.NameRequired, "force_noname": &s.Input.ForceNoname, "hide_mail": &s.Input.HideMail} {
		raw := v.Get(name)
		if raw != "true" && raw != "false" {
			return s, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		*p = raw == "true"
	}
	return s, nil
}
