// 管理者の板入力設定・投稿停止を、投稿と同じ板ワーカーで直列に保存する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/abuse"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"strings"
	"time"
)

// AdminBoardEdit はこの段階で変更できる全項目。スレッドの表示条件や保存期限は含めない。
type AdminBoardEdit struct {
	AutoReportsEnabled *bool                   `json:"auto_reports_enabled,omitempty"`
	Hidden             *bool                   `json:"hidden,omitempty"`
	NoReprint          *bool                   `json:"no_reprint,omitempty"`
	Identity           *AdminIdentitySettings  `json:"identity"`
	Input              boardInput              `json:"input"`
	Create             string                  `json:"create_policy"`
	Reply              string                  `json:"reply_policy"`
	Anonymous          *AdminAnonymousSettings `json:"anonymous"`
	Rates              *AdminRateSettings      `json:"rates"`
}

// AdminBoard は秘密を含まない板設定画面/API用の公開DTO。
type AdminBoard struct {
	ID       domain.ID      `json:"id"`
	Key      string         `json:"key"`
	Name     string         `json:"name"`
	Revision domain.U64     `json:"revision"`
	Settings AdminBoardEdit `json:"settings"`
}

func (b AdminBoard) ETag() string { return fmt.Sprintf(`"%s:%d"`, b.ID, b.Revision) }
func boardEdit(v boardValue) AdminBoardEdit {
	edit := AdminBoardEdit{Input: v.Settings.Input, Create: v.Settings.Posting.Create, Reply: v.Settings.Posting.Reply}
	if v.Settings.Presentation.Hidden != nil {
		value := *v.Settings.Presentation.Hidden
		edit.Hidden = &value
	}
	if v.Settings.Presentation.NoReprint != nil {
		value := *v.Settings.Presentation.NoReprint
		edit.NoReprint = &value
	}
	if v.Settings.Posting.AutoReports != nil {
		value := v.Settings.Posting.AutoReports.Enabled
		edit.AutoReportsEnabled = &value
	}
	edit.Anonymous = &AdminAnonymousSettings{v.Settings.Posting.Cookie, v.Settings.Posting.TokenWait}
	if nondefaultIdentity(v.Settings.Identity) {
		x := identityEdit(v.Settings.Identity)
		edit.Identity = &x
	}
	return edit
}
func (v AdminBoardEdit) validate() error {
	i := v.Input
	if v.Identity != nil {
		if e := v.Identity.validate(); e != nil {
			return e
		}
	}
	if e := v.rates().validate(); e != nil {
		return e
	}
	if e := v.anonymous().validate(); e != nil {
		return e
	}
	if i.NameBytes < 1 || i.NameBytes > 512 || i.MailBytes > 256 || i.TitleBytes < 1 || i.TitleBytes > 512 || i.BodyBytes < 1 || i.BodyBytes > 32768 || i.BodyLines < 2 || i.BodyLines > 1000 || i.BodyLines%2 != 0 || !validName(i.Noname) || i.NameRequired && i.ForceNoname || v.Create != "anyone" && v.Create != "disabled" && v.Create != "cap_only" || v.Reply != "anyone" && v.Reply != "disabled" && v.Reply != "cap_only" {
		return errors.New("invalid editable board settings")
	}
	dat, e := compat.DAT(domain.Post{Name: i.Noname}, "")
	if e != nil || bytes.Index(dat, []byte("<>")) > int(i.NameBytes) {
		return errors.New("default name exceeds name limit")
	}
	return nil
}

// validateEditedBoard は初期作成契約を維持し、編集できる項目と単調な版だけを許可する。
func validateEditedBoard(old, next []byte) error {
	var v boardValue
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if !validName(v.Name) || v.Description != "" || v.Status != "open" {
		return errors.New("unsupported board metadata")
	}
	if len(old) == 0 {
		if !validInitialBoardSettings(v.Settings) {
			return errors.New("unsupported initial board settings")
		}
		return nil
	}
	var p boardValue
	if e := strictjson.Decode(old, &p); e != nil {
		return e
	}
	if p.Settings.Version == ^domain.U64(0) || v.Settings.Version != p.Settings.Version+1 {
		return errors.New("board settings version mismatch")
	}
	if e := boardEdit(v).validate(); e != nil {
		return e
	}
	p.Settings.Version = v.Settings.Version
	p.Settings.Presentation.Hidden = v.Settings.Presentation.Hidden
	p.Settings.Presentation.NoReprint = v.Settings.Presentation.NoReprint
	p.Settings.Input = v.Settings.Input
	p.Settings.Identity = v.Settings.Identity
	if v.Settings.Identity.AllowFusianasan || v.Settings.Identity.Classifier != nil {
		return store.ErrCorrupt
	}
	if e := validateBoardAutoReports(p.Settings.Posting.AutoReports, v.Settings.Posting.AutoReports); e != nil {
		return e
	}
	p.Settings.Posting.AutoReports = v.Settings.Posting.AutoReports
	p.Settings.Posting.Create, p.Settings.Posting.Reply = v.Settings.Posting.Create, v.Settings.Posting.Reply
	p.Settings.Posting.Cookie, p.Settings.Posting.TokenWait = v.Settings.Posting.Cookie, v.Settings.Posting.TokenWait
	if !reflect.DeepEqual(p, v) {
		return errors.New("unsupported board setting change")
	}
	return nil
}

type adminBoardReceipt struct {
	ID      domain.ID   `json:"id"`
	Admin   domain.ID   `json:"admin_id"`
	Key     domain.Hash `json:"request_key_hmac"`
	Request domain.Hash `json:"request_hmac"`
	Result  AdminBoard  `json:"result"`
	Created domain.Time `json:"created_at_ns"`
	Expires domain.Time `json:"expires_at_ns"`
}

func validateAdminBoardReceipt(key string, old, next []byte) error {
	var v adminBoardReceipt
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if key != v.Key.String() || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Request == (domain.Hash{}) || v.Key == (domain.Hash{}) || v.Result.ID == (domain.ID{}) || !validBoardKey(v.Result.Key) || !validName(v.Result.Name) || v.Result.Revision == 0 || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 {
		return store.ErrCorrupt
	}
	if e := v.Result.Settings.validate(); e != nil {
		return e
	}
	if len(old) > 0 {
		var p adminBoardReceipt
		if e := strictjson.Decode(old, &p); e != nil {
			return e
		}
		if p.Expires > v.Created {
			return errors.New("board receipt still active")
		}
	}
	return nil
}
func (b *postingBoard) adminBoard() (AdminBoard, error) {
	if b.admission != nil {
		b.admission.mu.Lock()
		defer b.admission.mu.Unlock()
	}
	return b.adminBoardLocked()
}

// adminBoardLocked は投稿制限器がある場合にそのmutexを保持して呼ぶ。
func (b *postingBoard) adminBoardLocked() (AdminBoard, error) {
	row := b.control.State().Rows["board:state"]
	var v boardValue
	if e := strictjson.Decode(row.Value, &v); e != nil {
		return AdminBoard{}, e
	}
	edit := boardEdit(v)
	if b.admission != nil && b.admission.anonymous != nil {
		edit.Anonymous = &AdminAnonymousSettings{Mode: "required", Wait: v.Settings.Posting.TokenWait}
	}
	p := b.postingPolicy
	if p.At != 0 {
		edit.Rates = &p.Rates
	} else if b.admission != nil {
		defaults := defaultRateSettings()
		defaults = b.admission.policy.Defaults
		edit.Rates = &defaults
	}
	if b.admission != nil && b.admission.globalRates != nil {
		global := *b.admission.globalRates
		edit.Rates = &global
	}
	if edit.Anonymous != nil {
		edit.Anonymous.Wait = b.guardTokenWait(edit.Anonymous.Wait)
	}
	return b.presentAdminBoard(AdminBoard{b.owner, b.boardKey(), v.Name, row.Revision, edit}), nil
}

// adminBoardSettings はサイト認可を保持したまま板の確定値をコピーする。workerからサイトmutexは取らない。
func (r *Repository) adminBoardSettings(ctx context.Context, s adminauth.Session, id domain.ID) (AdminBoard, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.authorizeAdmin(s, "board_admin", id); e != nil {
		return AdminBoard{}, e
	}
	b := r.posting[id]
	if b == nil {
		return AdminBoard{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	v, e := b.worker.Submit(ctx, func() (any, error) { return b.adminBoard() })
	if e != nil {
		return AdminBoard{}, e
	}
	return v.(AdminBoard), nil
}

// updateAdminBoard は認可→板直列化→receipt→CAS→一括Syncの順で変更し、旧投稿を改変しない。
func (r *Repository) updateAdminBoard(ctx context.Context, s adminauth.Session, id domain.ID, edit AdminBoardEdit, etag, key string) (AdminBoard, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.authorizeAdmin(s, "board_admin", id); e != nil {
		return AdminBoard{}, e
	}
	if !adminRequestKey.MatchString(key) {
		return AdminBoard{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminBoard{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	if edit.Anonymous != nil && edit.Anonymous.Mode != "required" {
		return AdminBoard{}, &adminFailure{status: 422, code: "COOKIE_REQUIRED"}
	}
	if e := edit.validate(); e != nil {
		return AdminBoard{}, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
	}
	b := r.posting[id]
	if b == nil {
		return AdminBoard{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	raw, e := json.Marshal(edit)
	if e != nil {
		return AdminBoard{}, e
	}
	requestKey := identity.MAC(b.dedupKey[:], "oimo/admin-board-key/v1", s.Admin[:], id[:], []byte(key))
	request := identity.MAC(b.dedupKey[:], "oimo/admin-board-settings/v1", s.Admin[:], id[:], raw, []byte(etag))
	if edit.Anonymous != nil || edit.Rates != nil {
		// 古い版・同一再送では機能の初回保存を行わない。
		prior, e := b.worker.Submit(ctx, func() (any, error) {
			if row, ok := b.control.State().Rows["admin_receipt:"+requestKey.String()]; ok {
				var p adminBoardReceipt
				if e := strictjson.Decode(row.Value, &p); e != nil {
					return nil, e
				}
				if p.Created > domain.Time(time.Now().UnixNano()) {
					return nil, ErrPostingUnavailable
				}
				if p.Expires > domain.Time(time.Now().UnixNano()) {
					if p.Request != request {
						return nil, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
					}
					return p.Result, nil
				}
			}
			current, e := b.adminBoard()
			if e != nil {
				return nil, e
			}
			if etag != current.ETag() {
				return nil, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
			}
			return nil, nil
		})
		if e != nil {
			return AdminBoard{}, e
		}
		if prior != nil {
			return b.presentAdminBoard(prior.(AdminBoard)), nil
		}
		if e := r.ensureOnlinePostingPolicies(); e != nil {
			return AdminBoard{}, e
		}
	}
	if b.guard != nil {
		b.guard.mu.Lock()
		configured, settings := b.guard.configured, b.guard.settings
		b.guard.mu.Unlock()
		if configured {
			if edit.Rates != nil && *edit.Rates != settings.Rates || edit.Anonymous != nil && edit.Anonymous.Wait != settings.TokenWaitSeconds {
				return AdminBoard{}, &adminFailure{status: 422, code: "GLOBAL_ABUSE_SETTINGS"}
			}
			edit.Rates = nil
			edit.Anonymous = nil
		}
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		if r.admission != nil {
			r.admission.mu.Lock()
			defer r.admission.mu.Unlock()
		}
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		state := b.control.State()
		now := domain.Time(time.Now().UnixNano())
		if prior, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
			var p adminBoardReceipt
			if e := strictjson.Decode(prior.Value, &p); e != nil {
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
		current, e := b.adminBoardLocked()
		if e != nil {
			return nil, e
		}
		if etag != current.ETag() {
			return nil, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
		}
		count := 0
		for k := range state.Rows {
			if strings.HasPrefix(k, "admin_receipt:") {
				count++
			}
		}
		if count >= 200000 || state.Seq == ^domain.U64(0) {
			return nil, ErrPostingUnavailable
		}
		var board boardValue
		if e := strictjson.Decode(state.Rows["board:state"].Value, &board); e != nil {
			return nil, e
		}
		if board.Settings.Version == ^domain.U64(0) {
			return nil, ErrPostingUnavailable
		}
		// 先に機能の最低reader版を保存する。ここだけ完了して停止しても板は旧設定のまま安全に再開できる。
		var site siteState
		if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
			return nil, e
		}
		requiredReader := uint32(7)
		if edit.Identity != nil {
			requiredReader = 29
			if edit.Identity.Access != nil || networkRowsRequire32(edit.Identity.Networks) {
				requiredReader = 32
				if edit.Identity.Access.extended() {
					requiredReader = 34
				}
			}
		}
		if edit.Identity != nil && edit.Identity.Access != nil && edit.Identity.Access.DenyUnresolvedHost != nil {
			requiredReader = max(requiredReader, 37)
		}
		if edit.Anonymous != nil || edit.Rates != nil {
			requiredReader = max(requiredReader, 19)
		}
		if edit.Create == "cap_only" || edit.Reply == "cap_only" {
			requiredReader = max(requiredReader, 22)
		}
		if edit.Identity != nil {
			for _, row := range edit.Identity.Networks {
				if row.Provider != "" {
					requiredReader = max(requiredReader, 70)
				}
			}
		}
		if edit.Identity != nil && edit.Identity.DisplayCommands != nil {
			requiredReader = max(requiredReader, 74)
		}
		if edit.AutoReportsEnabled != nil {
			requiredReader = max(requiredReader, 84)
		}
		if edit.Hidden != nil {
			requiredReader = max(requiredReader, 76)
		}
		if edit.NoReprint != nil {
			requiredReader = max(requiredReader, 75)
		}
		if edit.Identity != nil && (specialNetworkRows(edit.Identity.Networks) || specialNetworkAccess(edit.Identity.Access)) {
			requiredReader = max(requiredReader, specialNetworkReader)
		}
		if edit.Identity != nil && (mixedNetworkRows(edit.Identity.Networks) || mixedNetworkAccess(edit.Identity.Access)) {
			requiredReader = max(requiredReader, mixedNetworkReader)
		}
		if site.MinimumReader < requiredReader {
			site.MinimumReader = requiredReader
			if e := appendControl(r.site, "board_settings_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{id.String()}); e != nil {
				r.stopped = true
				return nil, e
			}
		}
		board.Settings.Version++
		reportsChanged := edit.AutoReportsEnabled != nil && boardAutoReportsEnabled(board.Settings.Posting.AutoReports) != *edit.AutoReportsEnabled
		if edit.AutoReportsEnabled != nil && (reportsChanged || board.Settings.Posting.AutoReports == nil) {
			since := domain.Time(0)
			if board.Settings.Posting.AutoReports != nil {
				since = board.Settings.Posting.AutoReports.Since
			}
			if reportsChanged {
				if now <= since {
					return nil, ErrPostingUnavailable
				}
				since = now
			}
			board.Settings.Posting.AutoReports = &boardAutoReportSettings{Enabled: *edit.AutoReportsEnabled, Since: since}
		}
		if edit.Hidden != nil {
			value := *edit.Hidden
			board.Settings.Presentation.Hidden = &value
		}
		if edit.NoReprint != nil {
			value := *edit.NoReprint
			board.Settings.Presentation.NoReprint = &value
		}
		board.Settings.Input = edit.Input
		if edit.Identity != nil {
			access := board.Settings.Identity.Access
			if edit.Identity.Access != nil && access != nil {
				copy := *edit.Identity.Access
				if copy.DenyUnresolvedHost == nil {
					copy.DenyUnresolvedHost = access.DenyUnresolvedHost
				}
				if copy.DeniedKinds == nil {
					copy.DeniedKinds = access.DeniedKinds
				}
				if copy.DeniedCountries == nil {
					copy.DeniedCountries = access.DeniedCountries
				}
				edit.Identity.Access = &copy
			}
			if edit.Identity.DisplayCommands == nil {
				edit.Identity.DisplayCommands = cloneDisplayCommands(board.Settings.Identity.DisplayCommands)
			}
			board.Settings.Identity = edit.Identity.saved()
			if edit.Identity.Access == nil {
				board.Settings.Identity.Access = access
			}
		}
		board.Settings.Posting.Create, board.Settings.Posting.Reply = edit.Create, edit.Reply
		if edit.Anonymous != nil {
			board.Settings.Posting.Cookie, board.Settings.Posting.TokenWait = edit.Anonymous.Mode, edit.Anonymous.Wait
		}
		policy := b.postingPolicy
		if policy.At == 0 && b.admission != nil {
			policy.Rates = b.admission.ratesForBoard(id)
		}
		priorPolicy := policy
		if edit.Rates != nil {
			policy.Rates = *edit.Rates
		}
		policyChanged := policy.Rates != priorPolicy.Rates || priorPolicy.At == 0 && edit.Rates != nil
		if policyChanged {
			if now <= priorPolicy.At {
				return nil, abuse.ErrRateClock
			}
			policies, e := postingPolicies(state)
			if e != nil {
				return nil, e
			}
			if len(policies) >= 10000 {
				return nil, ErrPostingUnavailable
			}
			policy.ID = domain.NewID()
			policy.At = now
		}
		seq := state.Seq + 1
		resultEdit := boardEdit(board)
		if policy.At != 0 {
			resultEdit.Rates = &policy.Rates
		}
		result := AdminBoard{id, b.boardKey(), board.Name, seq, resultEdit}
		receipt := adminBoardReceipt{domain.NewID(), s.Admin, requestKey, request, result, now, now + 86400e9}
		changes := []store.Mutation{mutation("board", "state", board, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
		if policyChanged {
			changes = append(changes, mutation("posting_policy", policy.ID.String(), policy, nil))
		}
		for i := range changes {
			changes[i].ExpectedRevision = state.Rows[changes[i].Collection+":"+changes[i].Key].Revision
		}
		keyID := uint32(8)
		op := store.ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: state.Seq, Committed: now, Actor: domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "board_settings_update", Request: &request, Idempotency: &requestKey, KeyID: &keyID}, Mutations: changes, Result: store.ControlResult{Code: "board_updated", Targets: []string{id.String()}, RequestKey: &requestKey, Request: &request, KeyID: &keyID, Expires: &receipt.Expires}}
		encoded, e := json.Marshal(op)
		if e != nil {
			return nil, e
		}
		frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(seq), Records: []store.Record{{ID: receipt.ID, JSON: encoded}}})
		if e != nil {
			return nil, e
		}
		if b.control.Append(frame).Status != store.Durable {
			b.stopped = true
			return nil, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: receipt.ID}
		}
		b.autoReports.Store(board.Settings.Posting.AutoReports)
		if reportsChanged {
			for target := range r.autoReportVotes {
				if target.Board == id {
					delete(r.autoReportVotes, target)
				}
			}
		}
		if r.cfg.AutoReports != nil {
			snapshot, err := receiptSnapshotForBoard(r.cfg.Public.BaseURL, b.boardKey(), r.operations().Reports, board.Settings.Posting.AutoReports)
			if err != nil {
				b.stopped = true
				return nil, err
			}
			b.receipt.Store(snapshot)
		}
		b.noReprint.Store(board.Settings.Presentation.reprintDenied())
		b.hidden.Store(board.Settings.Presentation.unlisted())
		b.readingNetworks.Store(&board.Settings.Identity.Networks)
		if policyChanged {
			b.postingPolicy = policy
			if e := b.admission.applyBoardRatesLocked(id, policy.Rates, time.Unix(0, int64(now))); e != nil {
				b.stopped = true
				return nil, e
			}
		}
		return result, nil
	})
	if e != nil {
		return AdminBoard{}, e
	}
	return b.presentAdminBoard(value.(AdminBoard)), nil
}
