// 掲示板全体の荒らし対策をHTML/APIで編集し、入力エラー時も値を保持する。
package bootstrap

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"strconv"
)

type guardNumberField struct {
	Name, Label string
	Min, Max    int
}

var guardNumberFields = []guardNumberField{
	{"similar_window", "類似文を調べる期間（秒）", 1, 600}, {"similar_sample", "類似比較する直近の投稿数", 1, 128}, {"similar_threshold", "類似度の下限（％）", 50, 100}, {"similar_matches", "既存の類似投稿が何件あれば検出するか", 1, 128}, {"similar_min_runes", "類似比較する最低文字数", 3, 1000},
	{"flood_window", "埋め立てを調べる期間（秒）", 1, 600}, {"flood_thread", "一つのスレッドに許可する投稿数", 2, 4000}, {"flood_subject", "同じ投稿者・接続元に許可する投稿数（全板合計）", 2, 4000}, {"flood_share_min", "スレッド占有を判定する投稿者の最低投稿数", 2, 4000}, {"flood_share_percent", "スレッド占有率の下限（％）", 50, 100},
	{"reply_seconds", "返信の補充間隔（秒）", 1, 3600}, {"reply_burst", "返信の連投許容量", 1, 100}, {"create_seconds", "スレ立ての補充間隔（秒）", 1, 3600}, {"create_burst", "スレ立ての連投許容量", 1, 100}, {"create_window_limit", "スレ立ての61分上限", 1, 1000}, {"token_wait_seconds", "Cookie発行後の待ち時間（秒）", 0, 3600},
}

type guardPage struct {
	Values     url.Values
	Fields     []guardNumberField
	Events     []GuardEvent
	Message    string
	Configured bool
}

var guardTemplate = webui.Template("abuse-guard")

// guardFields は保存値を単位付きの管理入力へ変換する。
func guardFields(v AbuseGuardSettings) url.Values {
	values := []int{v.Similar.WindowSeconds, v.Similar.SamplePosts, v.Similar.ThresholdPercent, v.Similar.MatchPosts, v.Similar.MinRunes, v.Flood.WindowSeconds, v.Flood.ThreadPosts, v.Flood.SubjectPosts, v.Flood.ShareMinPosts, v.Flood.SharePercent, int(v.Rates.ReplySeconds), int(v.Rates.ReplyBurst), int(v.Rates.CreateSeconds), int(v.Rates.CreateBurst), int(v.Rates.CreateWindow), int(v.TokenWaitSeconds)}
	fields := url.Values{"similar_mode": {v.Similar.Mode}, "flood_mode": {v.Flood.Mode}, "exempt_caps": {strconv.FormatBool(v.ExemptCaps)}, "rate_enabled": {strconv.FormatBool(v.Rates.Enabled)}}
	for i, f := range guardNumberFields {
		fields.Set(f.Name, strconv.Itoa(values[i]))
	}
	return fields
}

// parseGuardFields は欠落・重複を許さないフォーム入力を完全な共通設定へ変換する。
func parseGuardFields(fields url.Values) (AbuseGuardSettings, error) {
	v := defaultAbuseGuard()
	v.Similar.Mode = fields.Get("similar_mode")
	v.Flood.Mode = fields.Get("flood_mode")
	for name, target := range map[string]*bool{"exempt_caps": &v.ExemptCaps, "rate_enabled": &v.Rates.Enabled} {
		raw := fields.Get(name)
		if raw != "true" && raw != "false" {
			return v, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		*target = raw == "true"
	}
	values := make([]int, len(guardNumberFields))
	for i, f := range guardNumberFields {
		raw := fields.Get(f.Name)
		n, err := strconv.Atoi(raw)
		if err != nil || strconv.Itoa(n) != raw || n < f.Min || n > f.Max {
			return v, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
		values[i] = n
	}
	v.Similar = SimilarSettings{v.Similar.Mode, values[0], values[1], values[2], values[3], values[4]}
	v.Flood = FloodSettings{v.Flood.Mode, values[5], values[6], values[7], values[8], values[9]}
	v.Rates = AdminRateSettings{v.Rates.Enabled, uint32(values[10]), uint32(values[11]), uint32(values[12]), uint32(values[13]), uint32(values[14])}
	v.TokenWaitSeconds = uint32(values[15])
	if v.validate() != nil {
		return v, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
	}
	return v, nil
}

// writeGuardPage は本文・秘密なしの検出情報と編集値をエスケープして表示する。
func writeGuardPage(w http.ResponseWriter, status int, page guardPage) {
	var body bytes.Buffer
	if err := executeAdminTemplate(w, &body, guardTemplate, page); err != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

// abuseGuardRoutes はサイト管理者専用の共通対策画面。保存は既存CSRF/CAS/再送規約に従う。
func (h *adminHandler) abuseGuardRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	const route = "/api/v1/abuse-guard"
	api := r.URL.Path == route
	if r.Method == "GET" {
		v, err := h.repo.adminAbuseGuard(s, nil, "", "")
		if err != nil {
			h.failure(w, r, err)
			return
		}
		w.Header().Set("ETag", v.ETag())
		w.Header().Set("X-CSRF-Token", s.CSRF(route))
		if api {
			adminJSON(w, 200, map[string]any{"data": v})
			return
		}
		fields := guardFields(v.Settings)
		fields.Set("csrf", s.CSRF(route))
		fields.Set("revision", v.ETag())
		fields.Set("request_id", domain.NewID().String())
		writeGuardPage(w, 200, guardPage{fields, guardNumberFields, v.Events, "", v.Configured})
		return
	}
	if api && r.Method != "PATCH" || !api && r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var edit AbuseGuardSettings
	var fields url.Values
	var etag, key string
	var err error
	if api {
		csrf, _, e := singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil || !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, _, err = singleRequestHeader(r.Header, "If-Match")
		if err != nil {
			h.fail(w, r, 400, "INVALID_REVISION")
			return
		}
		key, _, err = singleRequestHeader(r.Header, "Idempotency-Key")
		if err != nil {
			h.fail(w, r, 400, "INVALID_REQUEST_KEY")
			return
		}
		typ, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, params, e2 := mime.ParseMediaType(typ)
		if e != nil || e2 != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && params["charset"] != "utf-8" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
		if e != nil || strictjson.Decode(raw, &edit) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		names := []string{"csrf", "revision", "request_id", "similar_mode", "flood_mode", "exempt_caps", "rate_enabled"}
		for _, f := range guardNumberFields {
			names = append(names, f.Name)
		}
		fields, err = adminForm(w, r, 16<<10, names...)
		if err != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF(route, fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, key = fields.Get("revision"), fields.Get("request_id")
		edit, err = parseGuardFields(fields)
	}
	var v AdminAbuseGuard
	if err == nil {
		v, err = h.repo.adminAbuseGuard(s, &edit, etag, key)
	}
	if err != nil {
		if api || errors.Is(err, adminauth.ErrSession) {
			h.failure(w, r, err)
			return
		}
		status, message := 503, "結果を確認できません。同じ入力・要求IDで確認してください。"
		var f *adminFailure
		if errors.As(err, &f) {
			status = f.status
		}
		if status == 422 {
			message = "入力範囲を確認してください。類似件数は比較投稿数以下、補充間隔×連投許容量は3600以下、61分上限は連投許容量以上にしてください。"
		}
		if status == 412 || status == 409 {
			message = "設定または要求IDが競合しました。入力内容を控えて最新の設定を読み直してください。"
		}
		writeGuardPage(w, status, guardPage{fields, guardNumberFields, nil, message, false})
		return
	}
	if api {
		w.Header().Set("ETag", v.ETag())
		adminJSON(w, 200, map[string]any{"data": v})
	} else {
		http.Redirect(w, r, "/abuse-guard", 303)
	}
}
