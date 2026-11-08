// 板設定の共有が更新・同revisionの改変・破損・欠落を隠さないことを検査する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"strings"
	"testing"
)

func TestPostingFormSettingsFollowOriginalBytes(t *testing.T) {
	_, repo, info := postingRepositoryFixture(t)
	defer repo.Close()
	b := repo.posting[info.ID]
	_, err := b.worker.Submit(t.Context(), func() (any, error) {
		first, err := b.postingFormSettings()
		if err != nil {
			return nil, err
		}
		cache := b.formSettings
		if _, err = b.postingFormSettings(); err != nil || b.formSettings != cache {
			return nil, errors.New("unchanged settings decoded")
		}
		rows := b.control.State().Rows
		original := rows["board:state"]
		defer func() { rows["board:state"] = original }()
		changed := first
		changed.Name = "変更後"
		raw, err := json.Marshal(changed)
		if err != nil {
			return nil, err
		}
		rows["board:state"] = store.ControlRow{Revision: original.Revision, Value: raw}
		got, err := b.postingFormSettings()
		if err != nil || got.Name != "変更後" || b.formSettings == cache {
			return nil, errors.New("same-revision byte change hidden")
		}
		raw[0] = '!'
		if bytes.Equal(b.formSettings.raw, raw) {
			return nil, errors.New("cached bytes alias input")
		}
		if _, err = b.postingFormSettings(); err == nil {
			return nil, errors.New("corrupt settings hidden")
		}
		delete(rows, "board:state")
		if _, err = b.postingFormSettings(); err == nil {
			return nil, errors.New("missing settings hidden")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestLegacyFeedSettingsCacheRefresh はSETTING.TXTの読取共有が板設定の更新を隠さないことを確認する。
func TestLegacyFeedSettingsCacheRefresh(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "settingscache", "設定共有")
	if err != nil {
		t.Fatal(err)
	}
	get := func() string {
		t.Helper()
		req := modernWebReadTestRequest("GET", repo.cfg.Public.BaseURL+"/settingscache/SETTING.TXT", nil)
		res := httptest.NewRecorder()
		repo.SiteWebHandler(nil).ServeHTTP(res, req)
		if res.Code != 200 {
			t.Fatal(res.Code, res.Body.String())
		}
		return res.Body.String()
	}
	before := get()
	if get() != before {
		t.Fatal("unchanged settings response changed")
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/api/v1/boards/" + board.ID.String() + "/settings"
	res, body := c.request("GET", path, "", nil)
	var envelope struct {
		Data AdminBoard `json:"data"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil {
		t.Fatal(body)
	}
	edit := envelope.Data.Settings
	edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "verbose", Networks: []identity.NetworkClass{}}
	raw, _ := json.Marshal(edit)
	res, body = c.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	if after := get(); !strings.Contains(after, "BBS_SLIP=verbose") || after == before {
		t.Fatal("cached settings did not refresh", after)
	}
}
