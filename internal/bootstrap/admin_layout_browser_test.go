// 隔離した管理画面で、共通カード・一覧・詳細と既存フォームの保存経路をまとめて検証する。
package bootstrap

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestAdminLayoutBrowser は実データの依頼・案件と表示用の停止履歴で、各画面をブラウザ操作する。
func TestAdminLayoutBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-admin-layout-browser.mjs")
}

// TestAdminSettingsBrowser は設定変更の確認・詳細内の入力エラー・保存後の保持を実ブラウザで確認する。
func TestAdminSettingsBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-admin-settings-browser.mjs")
}

// TestAdminAssetsBrowser は実ルートで、対象ページに必要な資産だけが要求されることを検証する。
func TestAdminAssetsBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-admin-assets-browser.mjs")
}

// TestAdminExpiredSessionBrowser はHTML配信後に資産の認証が切れる競合を実ブラウザで検証する。
func TestAdminExpiredSessionBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-admin-expired-session-browser.mjs")
}

// TestAdminReauthenticationExpiryBrowser は10分経過相当の認証状態で表示と操作の復帰を確認する。
func TestAdminReauthenticationExpiryBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-admin-reauth-expiry-browser.mjs")
}

// TestAdminListBrowser はページ切替時の位置保持・件数変更・絞込み・編集中の値を検証する。
func TestAdminListBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-admin-list-browser.mjs")
}

// TestButtonColorsBrowser は管理画面の通常・ホバー配色を明暗両テーマで検証する。
func TestButtonColorsBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-button-colors-browser.mjs")
}

// runAdminLayoutBrowser は依頼・案件を含む隔離サーバーを用意し、指定した画面操作を実行する。
func runAdminLayoutBrowser(t *testing.T, scriptName string) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザ検証を有効化")
	}
	_, repo, reports, owner, thread := reportTestSetup(t)
	defer repo.Close()
	defer reports.server.Close()
	reportID, _ := createTestReport(t, reports, thread)
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("fixture login")
	}
	list, _ := c.request("GET", "/api/v1/evidence/cases", "", nil)
	key, _ := strconv.ParseUint(thread, 10, 64)
	now := time.Now()
	input := evidenceInput{Number: "CASE-LAYOUT-001", Organization: "表示確認の依頼機関", Reference: "REF-001", Reason: "管理画面の表示確認", Scope: disclosure.Scope{Board: owner, Thread: domain.U64(key), From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano()), Records: []domain.ID{}}}
	if res, _, body := evidencePost(t, c, "/api/v1/evidence/cases", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String()); res.StatusCode != 200 {
		t.Fatal("fixture case", res.StatusCode, body)
	}
	b := repo.posting[owner]
	_, err := b.worker.Submit(t.Context(), func() (any, error) {
		// 表示専用の履歴。投稿判定・永続規制の変更を試験対象に含めない。
		for _, state := range []string{"active", "expired", "revoked"} {
			id := domain.NewID()
			expires := now.Add(time.Hour)
			if state == "expired" {
				expires = now.Add(-time.Minute)
			}
			b.denials[id] = compiledDenial{rule: denialRule{ID: id, Conditions: []denialCondition{{Field: "body", Operator: "contains", Value: "表示確認用の条件"}}, Effect: denialEffect{Type: "deny"}, Scope: denialScope{Kind: "board", Board: owner}, Enabled: state != "revoked", Starts: domain.Time(now.Add(-time.Hour).UnixNano()), Expires: domain.Time(expires.UnixNano()), Reports: []autoReportEvidenceRef{{Operation: domain.NewID()}}}}
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scriptName == "test-admin-list-browser.mjs" {
		repo.mu.Lock()
		state, loadErr := loadNetworkState(repo.site.State())
		if loadErr == nil {
			state.Version++
			state.Config.Sources = defaultNetworkSources()
			state.Config.Enabled = false
			loadErr = repo.publishNetworks(state, nil, "network_refresh", nil)
		}
		repo.mu.Unlock()
		if loadErr != nil {
			t.Fatal(loadErr)
		}
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "http://localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	repo.cfg.Admin.Transport, repo.cfg.Admin.Origin, repo.cfg.Public.BaseURL = "public_path", origin+"/admin", origin
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "assets-browser")
	if err != nil {
		t.Fatal(err)
	}
	public := repo.SiteWebHandler(observer)
	server.Config.ConnContext = observer.ConnContext
	// 再認証の経過だけを再現する隔離用ゲート。本番のハンドラー・時計は変更しない。
	var expiryArmed, expiryTriggered atomic.Bool
	var expiredAssetCookie string
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scriptName == "test-admin-reauth-expiry-browser.mjs" {
			if r.URL.Path == "/__test/expire-reauth-during-assets" && r.Method == "POST" {
				expiryArmed.Store(true)
				w.WriteHeader(204)
				return
			}
			if expiryArmed.Load() && strings.HasPrefix(r.URL.Path, "/admin/web/assets/page/"+base64.RawURLEncoding.EncodeToString([]byte("/administrators"))+"/") {
				expiryTriggered.Store(true)
			}
			if expiryTriggered.Load() && strings.HasPrefix(r.URL.Path, "/admin/") {
				r.Header.Set("Cookie", (&http.Cookie{Name: "oimo_admin", Value: expiredAssetCookie}).String())
			}
		}

		if r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
			admin.Handler.ServeHTTP(w, r)
			return
		}
		public.ServeHTTP(w, r)
	})
	server.Start()
	script, err := filepath.Abs("../../scripts/" + scriptName)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_LAYOUT_URL="+origin+"/admin", "OIMO_TEST_PASSWORD="+adminTestSecret, "OIMO_LAYOUT_REPORT="+reportID.String(), "OIMO_LAYOUT_BOARD="+owner.String(), "OIMO_ASSETS_PUBLIC_URL="+origin, "OIMO_ASSETS_THREAD="+thread)
	if scriptName == "test-admin-reauth-expiry-browser.mjs" {
		session, lookupErr := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
		if lookupErr != nil {
			t.Fatal(lookupErr)
		}
		expiredAssetCookie = expiredReauthCookie(t, repo, session)
		command.Env = append(command.Env, "OIMO_EXPIRED_COOKIE="+expiredReauthCookie(t, repo, session))
	}

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	t.Log(string(output))
}

// TestReportRequestBrowser はレスから依頼・連続送信拒否・照会と間隔変更を実ブラウザーで検証する。
func TestReportRequestBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-report-request-browser.mjs")
}

// TestDateInputsBrowser は実フォームで期間・期限の選択と日時の精度・日本時間変換を検証する。
func TestDateInputsBrowser(t *testing.T) { runAdminLayoutBrowser(t, "test-date-inputs-browser.mjs") }
