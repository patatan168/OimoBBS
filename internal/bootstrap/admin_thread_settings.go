// 板ごとの新規スレッド上限と終了レスを、既存の板設定形式を変えずに保存する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strings"
	"time"
)

// EndingSettings は一つの終了レス。名前・メール・本文はHTMLではなく通常の文字列。
type EndingSettings struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Mail    string `json:"mail"`
	Body    string `json:"body"`
}

// ThreadSettings のレス上限は新規スレ作成時に固定し、終了レスは終了時の設定を使う。
type ThreadSettings struct {
	PostLimit uint32         `json:"user_post_limit"`
	First     EndingSettings `json:"ending_1"`
	Second    EndingSettings `json:"ending_2"`
}

// AdminThreadSettings は板IDと競合検出用の版を含む管理画面向けの設定。
type AdminThreadSettings struct {
	Board    domain.ID      `json:"board_id"`
	Revision domain.U64     `json:"revision"`
	Settings ThreadSettings `json:"settings"`
}

// ETag は終了レス設定の更新時に比較する版を返す。
func (v AdminThreadSettings) ETag() string { return fmt.Sprintf(`"%s:thread:%d"`, v.Board, v.Revision) }

// validate は通常文字列と最終DAT行の上限を保存前・復旧時に検査する。
func (v ThreadSettings) validate() error {
	if v.PostLimit < 1 || v.PostLimit > 10000 {
		return store.ErrCorrupt
	}
	for _, p := range []EndingSettings{v.First, v.Second} {
		if len(p.Name) > 512 || len(p.Mail) > 256 || len(p.Body) > 12000 || strings.Count(p.Body, "\n") > 100 {
			return store.ErrCorrupt
		}
		for _, f := range []struct {
			value string
			body  bool
		}{{p.Name, false}, {p.Mail, false}, {p.Body, true}} {
			normalized, e := compat.Normalize(f.value, f.body, false)
			if e != nil || normalized != f.value {
				return store.ErrCorrupt
			}
		}
		if p.Enabled && strings.TrimSpace(p.Body) == "" {
			return store.ErrCorrupt
		}
		dat, e := compat.DAT(domain.Post{Name: p.Name, Mail: p.Mail, Body: p.Body, Identity: domain.Identity{DateText: compat.DateText(time.Date(2099, 12, 31, 23, 59, 59, 999000000, time.UTC))}}, "")
		if e != nil || len(dat) > 4096 {
			return store.ErrCorrupt
		}
	}
	return nil
}

// threadSettings は板ワーカー内で設定を読み、未保存なら従来の初期値を返す。
func (b *postingBoard) threadSettings() (AdminThreadSettings, error) {
	result := AdminThreadSettings{Board: b.owner, Settings: ThreadSettings{PostLimit: 1000, First: EndingSettings{Enabled: true, Name: "OimoBBS", Body: "このスレッドは終了しました。"}, Second: EndingSettings{Name: "OimoBBS"}}}
	if row, ok := b.control.State().Rows["thread_settings:active"]; ok {
		if e := strictjson.Decode(row.Value, &result.Settings); e != nil {
			return result, e
		}
		result.Revision = row.Revision
	}
	return result, nil
}

// endResponses は有効な終了レスを順番に返す。空でもnilにせず、従来値への復帰を防ぐ。
func (v ThreadSettings) endResponses() []postinput.EndResponse {
	result := []postinput.EndResponse{}
	for _, p := range []EndingSettings{v.First, v.Second} {
		if p.Enabled {
			result = append(result, postinput.EndResponse{Name: p.Name, Mail: p.Mail, Body: p.Body})
		}
	}
	return result
}

type threadSettingsReceipt struct {
	ID      domain.ID           `json:"id"`
	Admin   domain.ID           `json:"admin_id"`
	Key     domain.Hash         `json:"request_key_hmac"`
	Request domain.Hash         `json:"request_hmac"`
	Result  AdminThreadSettings `json:"result"`
	Created domain.Time         `json:"created_at_ns"`
	Expires domain.Time         `json:"expires_at_ns"`
}

// validateThreadSettingsValue はcontrol行と再送記録の形式・保持期限を検査する。
func validateThreadSettingsValue(collection, key string, old, next json.RawMessage) error {
	if collection == "thread_settings" {
		if key != "active" {
			return store.ErrCorrupt
		}
		var v ThreadSettings
		if e := strictjson.Decode(next, &v); e != nil {
			return e
		}
		return v.validate()
	}
	var v threadSettingsReceipt
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if collection != "thread_settings_receipt" || key != v.Key.String() || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Result.Board == (domain.ID{}) || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.Result.Revision == 0 || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 {
		return store.ErrCorrupt
	}
	if e := v.Result.Settings.validate(); e != nil {
		return e
	}
	if len(old) > 0 {
		var before threadSettingsReceipt
		if e := strictjson.Decode(old, &before); e != nil {
			return e
		}
		if before.Expires > v.Created {
			return store.ErrCorrupt
		}
	}
	return nil
}

// adminThreadSettings は認可と板ワーカーの排他の下で設定を取得・保存する。edit=nilなら取得だけ。
func (r *Repository) adminThreadSettings(ctx context.Context, s adminauth.Session, id domain.ID, edit *ThreadSettings, etag, key string) (AdminThreadSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	role := "board_admin"
	if e := r.authorizeAdmin(s, role, id); e != nil {
		return AdminThreadSettings{}, e
	}
	b := r.posting[id]
	if b == nil {
		return AdminThreadSettings{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	if edit != nil {
		if !adminRequestKey.MatchString(key) {
			return AdminThreadSettings{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
		}
		if etag == "" {
			return AdminThreadSettings{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
		}
		if e := edit.validate(); e != nil {
			return AdminThreadSettings{}, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
		}
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		current, e := b.threadSettings()
		if e != nil || edit == nil {
			return current, e
		}
		state := b.control.State()
		now := domain.Time(time.Now().UnixNano())
		raw, _ := json.Marshal(edit)
		requestKey := identity.MAC(b.dedupKey[:], "oimo/thread-settings-key/v1", s.Admin[:], id[:], []byte(key))
		request := identity.MAC(b.dedupKey[:], "oimo/thread-settings/v1", s.Admin[:], id[:], raw, []byte(etag))
		if prior, ok := state.Rows["thread_settings_receipt:"+requestKey.String()]; ok {
			var p threadSettingsReceipt
			if e = strictjson.Decode(prior.Value, &p); e != nil {
				return nil, e
			}
			if p.Created > now {
				return nil, ErrPostingUnavailable
			}
			if p.Expires > now {
				if p.Request != request {
					return nil, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
				}
				return p.Result, nil
			}
		}
		if current.ETag() != etag {
			return nil, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
		}
		count := 0
		for name := range state.Rows {
			if strings.HasPrefix(name, "thread_settings_receipt:") {
				count++
			}
		}
		if count >= 200000 || state.Seq == ^domain.U64(0) {
			return nil, ErrPostingUnavailable
		}
		var site siteState
		if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
			return nil, e
		}
		if site.MinimumReader < 11 {
			site.MinimumReader = 11
			if e = appendControl(r.site, "thread_settings_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{id.String()}); e != nil {
				r.stopped = true
				return nil, e
			}
		}
		result := AdminThreadSettings{id, state.Seq + 1, *edit}
		receipt := threadSettingsReceipt{domain.NewID(), s.Admin, requestKey, request, result, now, now + 86400e9}
		mutations := []store.Mutation{mutation("thread_settings", "active", edit, nil), mutation("thread_settings_receipt", requestKey.String(), receipt, nil)}
		for i := range mutations {
			mutations[i].ExpectedRevision = state.Rows[mutations[i].Collection+":"+mutations[i].Key].Revision
		}
		keyID := uint32(8)
		op := store.ControlOperation{Schema: 1, Seq: state.Seq + 1, ExpectedSeq: state.Seq, Committed: now, Actor: domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "thread_settings_update", Request: &request, Idempotency: &requestKey, KeyID: &keyID}, Mutations: mutations, Result: store.ControlResult{Code: "thread_settings_updated", Targets: []string{id.String()}, RequestKey: &requestKey, Request: &request, KeyID: &keyID, Expires: &receipt.Expires}}
		encoded, e := json.Marshal(op)
		if e != nil {
			return nil, e
		}
		frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Seq), Records: []store.Record{{ID: receipt.ID, JSON: encoded}}})
		if e != nil {
			return nil, e
		}
		if commit := b.control.Append(frame); commit.Status != store.Durable {
			b.stopped = true
			return nil, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: receipt.ID}
		}
		return result, nil
	})
	if e != nil {
		return AdminThreadSettings{}, e
	}
	result, ok := value.(AdminThreadSettings)
	if !ok {
		return AdminThreadSettings{}, errors.New("invalid thread settings result")
	}
	return result, nil
}
