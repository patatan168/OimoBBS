// snapshotの現在値を、初期作成・更新の遷移規則と分けて検証する。
package bootstrap

import (
	"encoding/json"
	"reflect"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// snapshotSiteValue は現存するactive directoryも許可する。WALの初期作成規則は変更しない。
func snapshotSiteValue(collection, key string, old, next json.RawMessage) error {
	if len(old) != 0 || !noNull(next) {
		return store.ErrCorrupt
	}
	if collection == "report_store" {
		var a optionalLogActivation
		if strictjson.Decode(next, &a) != nil {
			return store.ErrCorrupt
		}
		initial := a
		initial.Phase = "preparing"
		raw, _ := json.Marshal(initial)
		return validateReportActivation(key, raw, next)
	}
	if collection == "required_gc" {
		_, e := decodeRequiredGCState(key, next)
		return e
	}
	if collection == "required_holds" {
		_, e := decodeRequiredHoldActivation(key, next)
		return e
	}
	if collection == "optional_http" || collection == "optional_loss" || collection == "optional_holds" {
		var v optionalLogActivation
		if strictjson.Decode(next, &v) != nil {
			return store.ErrCorrupt
		}
		if v.Phase == "active" {
			prior := v
			prior.Phase = "preparing"
			raw, _ := json.Marshal(prior)
			return validateSiteValue(collection, key, raw, next)
		}
		return validateSiteValue(collection, key, nil, next)
	}
	if collection == "cap" {
		var cap capValue
		if strictjson.Decode(next, &cap) != nil || key != cap.ID.String() {
			return store.ErrCorrupt
		}
		return validateCapState(cap)
	}
	if collection != "board_directory" {
		return validateSiteValue(collection, key, nil, next)
	}
	var id domain.ID
	if err := json.Unmarshal([]byte(`"`+key+`"`), &id); err != nil {
		return err
	}
	var v boardDirectory
	if err := strictjson.Decode(next, &v); err != nil {
		return err
	}
	if v.validateMetadata() != nil || v.CategoryID != nil && (*v.CategoryID == (domain.ID{}) || v.Status != "active") || (v.Status != "provisioning" && v.Status != "active") {
		return store.ErrCorrupt
	}
	return nil
}

// snapshotBoardValue は現在値の完全型・編集可能範囲を検査し、架空の旧値を作らない。
func snapshotBoardValue(collection, key string, old, next json.RawMessage) error {
	if collection == "cap_command" && len(old) == 0 {
		return snapshotCapCommandReceipt(key, next)
	}
	if len(old) != 0 || !noNull(next) {
		return store.ErrCorrupt
	}
	switch collection {
	case "board":
		if key != "state" {
			return store.ErrCorrupt
		}
		var v boardValue
		if err := strictjson.Decode(next, &v); err != nil {
			return err
		}
		if !validName(v.Name) || v.Description != "" || v.Status != "open" || v.Settings.Version == 0 {
			return store.ErrCorrupt
		}
		if v.Settings.Identity.AllowFusianasan || v.Settings.Identity.Classifier != nil {
			return store.ErrCorrupt
		}
		if err := boardEdit(v).validate(); err != nil {
			return err
		}
		if err := validateBoardAutoReports(nil, v.Settings.Posting.AutoReports); err != nil {
			return err
		}
		expected := defaultBoardSettings()
		if v.Settings.Version == 1 {
			expected = initialBoardSettings(v.Settings.Posting.Create)
		}
		if v.Settings.Version > 1 {
			expected.Version = v.Settings.Version
			expected.Presentation.Hidden = v.Settings.Presentation.Hidden
			expected.Presentation.NoReprint = v.Settings.Presentation.NoReprint
			expected.Input = v.Settings.Input
			expected.Identity = v.Settings.Identity
			expected.Posting.AutoReports = v.Settings.Posting.AutoReports
			expected.Posting.Create = v.Settings.Posting.Create
			expected.Posting.Reply = v.Settings.Posting.Reply
			expected.Posting.Cookie = v.Settings.Posting.Cookie
			expected.Posting.TokenWait = v.Settings.Posting.TokenWait
		}
		if !reflect.DeepEqual(expected, v.Settings) {
			return store.ErrCorrupt
		}
		return nil
	case "key_watermark":
		if key != "thread" {
			return store.ErrCorrupt
		}
		var v struct {
			Last domain.U64 `json:"last_reserved_key"`
		}
		return strictjson.Decode(next, &v)
	case "bump_watermark":
		if key != "ranking" {
			return store.ErrCorrupt
		}
		var v struct {
			Last domain.U64 `json:"last_removed_bump"`
		}
		return strictjson.Decode(next, &v)
	case "board_rule":
		var v denialRule
		if err := strictjson.Decode(next, &v); err != nil {
			return err
		}
		if key != v.ID.String() {
			return store.ErrCorrupt
		}
		_, err := compileDenial(v)
		return err
	default:
		return validateBoardValue(collection, key, nil, next)
	}
}

// snapshotValues は候補の所有種別に応じた状態検証器。元WALの値との比較には依存しない。
func snapshotValues(kind string) store.ValueValidator {
	switch kind {
	case "site":
		return snapshotSiteValue
	case "board":
		return snapshotBoardValue
	default:
		return func(string, string, json.RawMessage, json.RawMessage) error { return store.ErrCorrupt }
	}
}

// inspectSnapshotState は保存元を使わず、必須行と外部の所有者・作成jobを照合する。
func (r *Repository) inspectSnapshotState(owner AuditTransferOwner, state store.ControlState) error {
	if owner.Kind == "site" {
		_, err := inspectSiteState(state, owner.Owner, r.cfg.Public.BaseURL)
		return err
	}
	dirs, err := siteDirectories(r.site.State())
	if err != nil {
		return err
	}
	dir := dirs[owner.Owner]
	if dir == nil || owner.Kind != "board" {
		return store.ErrCorrupt
	}
	job, err := inspectJob(r.cfg.DataDir, dir.JobID)
	if err != nil {
		return err
	}
	if job.Parameters.BoardID != owner.Owner {
		return store.ErrCorrupt
	}
	_, err = inspectBoardState(state, job, dir)
	return err
}
