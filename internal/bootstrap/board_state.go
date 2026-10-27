// 板directory・板control・作成jobの完全型を検証する。板編集は許可項目と版を別途照合する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strconv"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

var boardKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func validBoardKey(k string) bool {
	return boardKeyPattern.MatchString(k) && k != "test" && k != "web" && k != "admin"
}

type boardDirectory struct {
	Key        string     `json:"key"`
	Aliases    []string   `json:"aliases"`
	Status     string     `json:"status"`
	CategoryID *domain.ID `json:"category_id"`
	JobID      domain.ID  `json:"job_id"`
}
type boardValue struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Status      string        `json:"status"`
	Settings    boardSettings `json:"settings"`
}
type boardParameters struct {
	BoardID    domain.ID     `json:"board_id"`
	Key        string        `json:"key"`
	Name       string        `json:"name"`
	CategoryID *domain.ID    `json:"category_id"`
	Settings   boardSettings `json:"settings"`
}
type provisionTotals struct {
	Total     uint32 `json:"total"`
	Succeeded uint32 `json:"succeeded"`
	Failed    uint32 `json:"failed"`
	Pending   uint32 `json:"pending"`
}
type provisionJob struct {
	ID         domain.ID       `json:"id"`
	Kind       string          `json:"kind"`
	State      string          `json:"state"`
	OwnerAdmin *domain.ID      `json:"owner_admin_id"`
	Boards     []domain.ID     `json:"board_ids"`
	Created    domain.Time     `json:"created_at_ns"`
	Started    *domain.Time    `json:"started_at_ns"`
	Finished   *domain.Time    `json:"finished_at_ns"`
	Request    domain.Hash     `json:"request_hmac"`
	Parameters boardParameters `json:"parameters"`
	Cursor     domain.U64      `json:"children_cursor"`
	Totals     provisionTotals `json:"totals"`
	LastError  *string         `json:"last_error"`
	Expires    *domain.Time    `json:"expires_at_ns"`
}

func validateDirectory(key string, old, next json.RawMessage) error {
	var id domain.ID
	if err := json.Unmarshal([]byte(strconv.Quote(key)), &id); err != nil {
		return err
	}
	var v boardDirectory
	if err := strictjson.Decode(next, &v); err != nil {
		return err
	}
	if !validBoardKey(v.Key) || len(v.Aliases) != 0 || v.CategoryID != nil && *v.CategoryID == (domain.ID{}) || (v.Status != "provisioning" && v.Status != "active") {
		return errors.New("unsupported board directory")
	}
	if len(old) == 0 {
		if v.Status != "provisioning" || v.CategoryID != nil {
			return errors.New("board must start provisioning")
		}
		return nil
	}
	var prior boardDirectory
	if err := strictjson.Decode(old, &prior); err != nil {
		return err
	}
	if prior.Key != v.Key || prior.JobID != v.JobID || (prior.Status != "provisioning" && prior.Status != "active") || v.Status != "active" || prior.Status == "provisioning" && v.CategoryID != nil {
		return errors.New("invalid board activation")
	}
	return nil
}
func validateBoardValue(collection, key string, old, next json.RawMessage) error {
	if !noNull(next) {
		if collection == "cap_command" || collection == "admin_receipt" || collection == "rule_receipt" || collection == "thread_settings_receipt" || collection == "local_rules_receipt" {
			if len(old) == 0 {
				return store.ErrCorrupt
			}
			if collection == "cap_command" {
				return snapshotCapCommandReceipt(key, old)
			}
			return validateBoardValue(collection, key, nil, old)
		}
		return errors.New("required board state cannot be deleted")
	}
	switch collection {
	case "cap_command":
		return validateCapCommandReceipt(key, old, next)
	case "post_evidence_query":
		return validatePostEvidenceAudit(key, old, next)
	case "carry_retirement":
		return validateBodyCarryRetirementAnchor(key, old, next)
	case "evidence_checkpoint":
		return validateRequiredCheckpointAnchor(key, old, next)
	case "local_rules", "local_rules_receipt":
		return validateLocalRulesValue(collection, key, old, next)
	case "thread_settings", "thread_settings_receipt":
		return validateThreadSettingsValue(collection, key, old, next)
	case "posting_policy":
		return validateBoardPostingPolicy(key, old, next)
	case "board_rule":
		return validateDenialRule(key, old, next)
	case "rule_receipt":
		return validateRuleReceipt(key, old, next)
	case "admin_receipt":
		return validateAdminBoardReceipt(key, old, next)
	case "board":
		if key != "state" {
			return store.ErrCorrupt
		}
		return validateEditedBoard(old, next)
	case "key_watermark":
		if key != "thread" {
			return store.ErrCorrupt
		}
		var v struct {
			Last domain.U64 `json:"last_reserved_key"`
		}
		if err := strictjson.Decode(next, &v); err != nil {
			return err
		}
		if len(old) == 0 {
			if v.Last != 0 {
				return store.ErrCorrupt
			}
			return nil
		}
		var before struct {
			Last domain.U64 `json:"last_reserved_key"`
		}
		if err := strictjson.Decode(old, &before); err != nil {
			return err
		}
		if v.Last <= before.Last {
			return errors.New("thread key watermark must increase")
		}
	case "bump_watermark":
		if key != "ranking" {
			return store.ErrCorrupt
		}
		if len(old) > 0 {
			return validateBumpWatermarkUpdate(key, old, next)
		}
		var v struct {
			Last domain.U64 `json:"last_removed_bump"`
		}
		if err := strictjson.Decode(next, &v); err != nil {
			return err
		}
		if v.Last != 0 {
			return store.ErrCorrupt
		}
	default:
		return errors.New("unsupported board collection")
	}
	return nil
}
func validateProvisionJob(collection, key string, old, next json.RawMessage) error {
	if collection != "job" || !noNull(next) {
		return store.ErrCorrupt
	}
	var v provisionJob
	if err := strictjson.Decode(next, &v); err != nil {
		return err
	}
	if key != v.ID.String() || v.Kind != "provision_board" || v.OwnerAdmin != nil && *v.OwnerAdmin == (domain.ID{}) || len(v.Boards) != 1 || v.Boards[0] != v.Parameters.BoardID || !validBoardKey(v.Parameters.Key) || !validName(v.Parameters.Name) || v.Parameters.CategoryID != nil || !validInitialBoardSettings(v.Parameters.Settings) || v.Parameters.Settings.Posting.Create == "cap_only" && v.OwnerAdmin == nil || v.LastError != nil {
		return errors.New("invalid board provisioning job")
	}
	switch v.State {
	case "running":
		if v.Started == nil || *v.Started != v.Created || v.Finished != nil || v.Expires != nil || v.Cursor != 0 || v.Totals != (provisionTotals{Total: 1, Pending: 1}) {
			return store.ErrCorrupt
		}
	case "completed":
		if v.Started == nil || *v.Started != v.Created || v.Finished == nil || *v.Finished < v.Created || v.Expires == nil || int64(*v.Finished) > 1<<63-1-30*86400*1e9 || *v.Expires != *v.Finished+domain.Time(30*86400*1e9) || v.Cursor != 1 || v.Totals != (provisionTotals{Total: 1, Succeeded: 1}) {
			return store.ErrCorrupt
		}
	default:
		return errors.New("unsupported provision job state")
	}
	if len(old) == 0 {
		if v.State != "running" {
			return store.ErrCorrupt
		}
		return nil
	}
	var before provisionJob
	if err := strictjson.Decode(old, &before); err != nil {
		return err
	}
	if before.State != "running" || v.State != "completed" {
		return store.ErrCorrupt
	}
	original := v
	original.State = before.State
	original.Finished = before.Finished
	original.Expires = before.Expires
	original.Cursor = before.Cursor
	original.Totals = before.Totals
	if !reflect.DeepEqual(original, before) {
		return errors.New("provisioning request changed")
	}
	return nil
}
