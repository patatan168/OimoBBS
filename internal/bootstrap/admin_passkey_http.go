// パスキーの本人登録・削除・ログイン・再認証を既存の管理HTTP境界へ接続する。
package bootstrap

import (
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
)

const passkeyRoute = "/api/v1/passkey/"

type passkeyInput struct {
	// Login は旧画面との互換用。パスキー認証の対象者の決定には使わない。
	Login string `json:"login,omitempty"`
	Name  string `json:"name,omitempty"`
	ID    string `json:"id,omitempty"`
}
type passkeyView struct{ Name, ID, Created string }
type passkeysPage struct {
	OTPCSRF                                             string
	OTPEnabled, PasswordDisabled, StrongReauthenticated bool
	CSRF                                                string
	Rows                                                []passkeyView
	Reauthenticated                                     bool
}

var passkeysTemplate = webui.Template("passkeys")

func (h *adminHandler) passkeyRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session, raw, ip string) {
	wa, err := h.webAuthn()
	if err != nil {
		h.fail(w, r, 503, "PASSKEY_UNAVAILABLE")
		return
	}
	if r.URL.Path == "/passkeys" && r.Method == "GET" {
		h.passkeyPage(w, r, s, wa.Config.RPID)
		return
	}
	kind, step, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, passkeyRoute), "/")
	if r.Method != "POST" || !ok || (kind != "login" && kind != "register" && kind != "reauth" && kind != "remove") || (step != "begin" && step != "finish") || kind == "remove" && step != "finish" {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	if kind == "login" {
		raw, err = singlePostingCookie(r.Header, "oimo_admin_login", 43)
		if err != nil {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
	} else {
		csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
		if err != nil || !s.CheckCSRF(passkeyRoute, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		if (kind == "register" || kind == "remove") && !s.Reauthenticated(time.Now()) {
			h.fail(w, r, 403, "REAUTHENTICATION_REQUIRED")
			return
		}
	}
	typ, _, err := singleRequestHeader(r.Header, "Content-Type")
	media, _, parseErr := mime.ParseMediaType(typ)
	if err != nil || parseErr != nil || media != "application/json" {
		h.fail(w, r, 415, "JSON_REQUIRED")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if step == "begin" || kind == "remove" {
		body, err := io.ReadAll(r.Body)
		in, decodeErr := decodePasskeyInput(body, kind)
		if err != nil || decodeErr != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		if kind == "remove" {
			h.removePasskey(w, r, s, in, wa.Config.RPID)
			return
		}
		h.beginPasskey(w, r, s, raw, ip, kind, in, wa)
		return
	}
	h.finishPasskey(w, r, s, raw, ip, kind, wa)
}

func (h *adminHandler) passkeyPage(w http.ResponseWriter, r *http.Request, s adminauth.Session, rp string) {
	h.repo.mu.Lock()
	a, err := h.repo.currentAdminSession(s)
	var keys adminPasskeySet
	if err == nil {
		keys, _, err = h.repo.passkeysLocked(a, rp)
	}
	var security adminSecurityState
	if err == nil {
		security, _, err = h.repo.adminSecurityLocked(a)
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	page := passkeysPage{OTPCSRF: s.CSRF(otpRoute), OTPEnabled: len(security.OTPSealed) > 0, PasswordDisabled: security.PasswordDisabled, StrongReauthenticated: s.StrongReauthenticated(time.Now()), CSRF: s.CSRF(passkeyRoute), Reauthenticated: s.Reauthenticated(time.Now())}
	for _, key := range keys.Keys {
		page.Rows = append(page.Rows, passkeyView{Name: key.Name, Created: time.Unix(0, int64(key.Created)).In(domain.JST).Format("2006/01/02 15:04"), ID: base64.RawURLEncoding.EncodeToString(key.Credential.ID)})
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(200)
	_ = executeAdminTemplate(w, w, passkeysTemplate, page)
}

// beginPasskey はログインnonceまたはセッションCSRFの検証後だけチャレンジを発行する。
func (h *adminHandler) beginPasskey(w http.ResponseWriter, r *http.Request, s adminauth.Session, binding, ip, kind string, in passkeyInput, wa *webauthn.WebAuthn) {
	if kind == "login" {
		h.beginPasskeyLogin(w, r, binding, ip, wa)
		return
	}
	if err := h.auth.AttemptPasskey(ip, time.Now()); err != nil {
		h.failure(w, r, err)
		return
	}
	h.repo.mu.Lock()
	a, err := h.repo.currentAdminSession(s)
	var keys adminPasskeySet
	var revision domain.U64
	if err == nil && a.ID != (domain.ID{}) {
		keys, revision, err = h.repo.passkeysLocked(a, wa.Config.RPID)
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if a.ID == (domain.ID{}) || kind != "register" && len(keys.Keys) == 0 {
		h.fail(w, r, 401, "PASSKEY_AUTHENTICATION_FAILED")
		return
	}
	if kind == "register" && (!validName(in.Name) || len(keys.Keys) >= 16) {
		h.fail(w, r, 422, "INVALID_PASSKEY_NAME_OR_CAPACITY")
		return
	}
	user := passkeyAccount(a, keys)
	var options any
	var session *webauthn.SessionData
	if kind == "register" {
		options, session, err = wa.BeginRegistration(user, webauthn.WithExclusions(webauthn.Credentials(user.keys).CredentialDescriptors()))
	} else {
		options, session, err = wa.BeginDiscoverableLogin()
	}
	if err != nil {
		h.fail(w, r, 400, "PASSKEY_UNAVAILABLE")
		return
	}
	token, err := h.passkeys.put(passkeyCeremony{Kind: kind, Binding: binding, Name: in.Name, Account: a, Revision: revision, Session: *session}, time.Now())
	if err != nil {
		h.failure(w, r, err)
		return
	}
	http.SetCookie(w, h.adminCookie("oimo_admin_passkey", token, 120))
	adminJSON(w, 200, options)
}

// finishPasskey は署名・Origin・RP・本人確認を検証し、現在の世代と鍵一覧を再検査する。
func (h *adminHandler) finishPasskey(w http.ResponseWriter, r *http.Request, s adminauth.Session, binding, ip, kind string, wa *webauthn.WebAuthn) {
	action, outcome := "login", "failed"
	accountID := ""
	if kind != "login" {
		action = "reauth"
	}
	defer func() { h.security.Record(action, outcome, ip, accountID, time.Now()) }()
	token, err := singlePostingCookie(r.Header, "oimo_admin_passkey", 43)
	flow, ok := h.passkeys.take(token, kind, binding, time.Now())
	http.SetCookie(w, h.adminCookie("oimo_admin_passkey", "", -1))
	if err != nil || !ok {
		h.fail(w, r, 401, "PASSKEY_CHALLENGE_EXPIRED")
		return
	}
	verified, err := h.verifyPasskey(flow, r, wa)
	a, keys, revision, credential := verified.Account, verified.Keys, verified.Revision, verified.Credential
	if err != nil || credential == nil || credential.Authenticator.CloneWarning {
		h.fail(w, r, 401, "PASSKEY_AUTHENTICATION_FAILED")
		return
	}
	if kind == "register" {
		if len(keys.Keys) >= 16 || passkeyIndex(keys, credential.ID) >= 0 {
			h.fail(w, r, 409, "PASSKEY_ALREADY_REGISTERED")
			return
		}
		keys.Keys = append(keys.Keys, adminPasskey{Name: flow.Name, Created: domain.Time(time.Now().UnixNano()), Credential: *credential})
	} else {
		index := passkeyIndex(keys, credential.ID)
		if index < 0 {
			h.fail(w, r, 401, "PASSKEY_CHANGED")
			return
		}
		keys.Keys[index].Credential = *credential
	}
	h.repo.mu.Lock()
	if kind != "login" {
		_, err = h.repo.currentAdminSession(s)
	}
	if err == nil && kind == "register" && !s.Reauthenticated(time.Now()) {
		err = &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
	}
	if err == nil {
		err = h.savePasskeysLocked(a, revision, keys, "administrator_passkey_"+kind)
	}
	var cookie string
	if err == nil && kind == "login" {
		cookie, _, err = h.auth.Create(a.ID, a.Generation, time.Now())
	}
	if err == nil && kind == "reauth" {
		cookie, _, err = h.auth.MarkStronglyReauthenticated(binding, s, time.Now())
	}
	h.repo.mu.Unlock()
	if err != nil {
		outcome = "error"
		h.failure(w, r, err)
		return
	}
	if cookie != "" {
		http.SetCookie(w, h.adminCookie("oimo_admin", cookie, 8*3600))
	}
	if kind == "login" {
		if old, e := singlePostingCookie(r.Header, "oimo_admin", 43); e == nil {
			h.auth.Delete(old)
		}
		http.SetCookie(w, h.adminCookie("oimo_admin_login", "", -1))
	}
	outcome = "success"
	accountID = a.ID.String()
	landing := "/auto-reports"
	if a.Role == "site_admin" {
		landing = "/"
	} else if a.Role == "board_admin" {
		landing = "/boards"
	}
	adminJSON(w, 200, map[string]any{"ok": true, "redirect": landing})
}

func (h *adminHandler) removePasskey(w http.ResponseWriter, r *http.Request, s adminauth.Session, in passkeyInput, rp string) {
	id, err := base64.RawURLEncoding.Strict().DecodeString(in.ID)
	if err != nil || len(id) == 0 {
		h.fail(w, r, 400, "INVALID_PASSKEY_ID")
		return
	}
	h.repo.mu.Lock()
	a, err := h.repo.currentAdminSession(s)
	var keys adminPasskeySet
	var revision domain.U64
	if err == nil {
		keys, revision, err = h.repo.passkeysLocked(a, rp)
	}
	if err == nil {
		index := passkeyIndex(keys, id)
		if !s.Reauthenticated(time.Now()) {
			err = &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
		} else if index < 0 {
			err = &adminFailure{status: 404, code: "PASSKEY_NOT_FOUND"}
		} else {
			keys.Keys = append(keys.Keys[:index], keys.Keys[index+1:]...)
			err = h.savePasskeysLocked(a, revision, keys, "administrator_passkey_remove")
		}
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	http.SetCookie(w, h.adminCookie("oimo_admin", "", -1))
	adminJSON(w, 200, map[string]any{"ok": true, "redirect": "/login"})
}

// decodePasskeyInput は操作ごとに必要なキーだけを必須にし、未知・重複キーを拒否する。
func decodePasskeyInput(body []byte, kind string) (passkeyInput, error) {
	switch kind {
	case "login":
		if err := strictjson.Decode(body, &struct{}{}); err == nil {
			return passkeyInput{}, nil
		}
		// 旧画面の入力名は構造だけ検査し、認証対象は認証器の応答から決める。
		var in struct {
			Login string `json:"login,omitempty"`
		}
		err := strictjson.Decode(body, &in)
		return passkeyInput{}, err
	case "register":
		var in struct {
			Name string `json:"name"`
		}
		err := strictjson.Decode(body, &in)
		return passkeyInput{Name: in.Name}, err
	case "remove":
		var in struct {
			ID string `json:"id"`
		}
		err := strictjson.Decode(body, &in)
		return passkeyInput{ID: in.ID}, err
	default:
		return passkeyInput{}, strictjson.Decode(body, &struct{}{})
	}
}
