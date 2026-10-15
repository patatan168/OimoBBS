// site controlの初期状態と鍵メタデータを完全型で検証する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const readerVersion = 87

// storageFormatVersion は旧サイトの読み込み・移行を拒否する初期化完了印の版。
const storageFormatVersion = 2

var purposes = []string{"public_id", "slip_net", "slip_ua", "anon", "confirm", "csrf", "rate", "dedup", "cap", "evidence_sign"}

type category struct {
	ID    domain.ID `json:"id"`
	Name  string    `json:"name"`
	Order uint32    `json:"order"`
}
type siteState struct {
	ID             domain.ID  `json:"site_id"`
	Name           string     `json:"name"`
	BaseURL        string     `json:"base_url"`
	Categories     []category `json:"category"`
	Terms          domain.U64 `json:"terms_revision"`
	PublicRevision domain.U64 `json:"public_revision"`
	MinimumReader  uint32     `json:"minimum_reader_version"`
}
type keyMetadata struct {
	ID          uint32       `json:"id"`
	Purpose     string       `json:"purpose"`
	Status      string       `json:"status"`
	Created     domain.Time  `json:"created_at_ns"`
	IssueUntil  *domain.Time `json:"issue_until_ns"`
	VerifyUntil *domain.Time `json:"verify_until_ns"`
}

// instanceは最後に保存する初期化完了印。可変設定や秘密を重複保存しない。
type instance struct {
	Schema        uint32      `json:"schema"`
	SiteID        domain.ID   `json:"site_id"`
	MasterSHA     domain.Hash `json:"master_sha256"`
	SigningPublic domain.Hash `json:"evidence_public_key"`
}

func validName(name string) bool {
	if !utf8.ValidString(name) || strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 128 {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func validateSiteValue(collection, key string, old, next json.RawMessage) error {
	if !noNull(next) {
		if collection == "posting_violation" || collection == "abuse_guard_receipt" || collection == "operations_receipt" || collection == "admin_receipt" || collection == "token_issue" || collection == "token_reissue" || collection == "token_revocation" {
			if len(old) == 0 {
				return store.ErrCorrupt
			}
			return validateSiteValue(collection, key, nil, old)
		}
		return errors.New("required site object cannot be deleted")
	}
	switch collection {
	case "waf":
		return validateWAFValue(key, next)
	case "posting_violation":
		return validateViolationValue(key, old, next)
	case "abuse_guard", "abuse_guard_receipt", "global_posting_policy":
		return validateGuardValue(collection, key, old, next)
	case "reading_access":
		return validateReadingValue(key, next)
	case "operations", "operations_receipt":
		return validateOperationsValue(collection, key, old, next)
	case "report_store":
		return validateReportActivation(key, old, next)
	case optionalHoldRetirementCollection:
		return validateOptionalHoldRetirementRegistration(key, old, next)
	case "case_retirement":
		return validateCaseRetirementRegistration(key, old, next)
	case "required_gc":
		return validateRequiredGCState(key, old, next)
	case "required_holds":
		return validateRequiredHoldActivation(key, old, next)
	case "optional_holds":
		return validateOptionalHoldActivation(key, old, next)
	case "optional_loss":
		return validateOptionalLossActivation(key, old, next)
	case "optional_http":
		return validateOptionalLogActivation(key, old, next)
	case "network":
		return validateNetworkValue(key, old, next)
	case "slip_policy":
		return validateSlipPolicy(key, old, next)
	case "expiry_watermark":
		return validateControlExpiryWatermark(key, old, next)
	case "cap":
		return validateCapValue(key, old, next)
	case "administrator":
		return validateAdministrator(key, old, next)
	case "admin_receipt":
		return validateAdminReceipt(key, old, next)
	case "anon_policy", "token_issue", "token_reissue", "token_revocation":
		return validateAnonymousValue(collection, key, old, next)
	case "rate_policy":
		if key != "active" || len(old) != 0 {
			return errors.New("rate policy is immutable")
		}
		_, err := validateAdmission(next)
		return err
	case "board_directory":
		return validateDirectory(key, old, next)
	case "site":
		if key != "state" {
			return store.ErrCorrupt
		}
		var v siteState
		if err := strictjson.Decode(next, &v); err != nil {
			return err
		}
		if !validName(v.Name) || v.Terms == 0 || v.PublicRevision == 0 || (v.MinimumReader < 3 || v.MinimumReader > readerVersion) || len(v.Categories) > 256 {
			return errors.New("invalid site state or unsupported reader version")
		}
		if _, err := parseOrigin(v.BaseURL); err != nil {
			return err
		}
		seen := map[domain.ID]bool{}
		names := map[string]bool{}
		for index, c := range v.Categories {
			if !validName(c.Name) || c.ID == (domain.ID{}) || seen[c.ID] || v.MinimumReader >= 77 && (names[c.Name] || c.Order != uint32(index)) {
				return store.ErrCorrupt
			}
			seen[c.ID] = true
			names[c.Name] = true
		}
		if len(old) != 0 {
			var prior siteState
			if err := strictjson.Decode(old, &prior); err != nil {
				return err
			}
			if v.ID != prior.ID || v.Terms < prior.Terms || v.PublicRevision < prior.PublicRevision || v.MinimumReader < prior.MinimumReader {
				return errors.New("site identity or revision regression")
			}
		}
	case "key_metadata":
		var v keyMetadata
		if err := strictjson.Decode(next, &v); err != nil {
			return err
		}
		if v.ID == 0 || v.ID > uint32(len(purposes)) || key != strconv.FormatUint(uint64(v.ID), 10) || v.Purpose != purposes[v.ID-1] || v.Status != "active" || v.IssueUntil != nil || v.VerifyUntil != nil {
			return errors.New("unsupported key metadata or rotation")
		}
		if len(old) != 0 {
			var prior keyMetadata
			if err := strictjson.Decode(old, &prior); err != nil {
				return err
			}
			if prior != v {
				return errors.New("key metadata replacement is not supported yet")
			}
		}
	default:
		return errors.New("site collection is not supported by bootstrap yet")
	}
	return nil
}

func initialFrame(id domain.ID, name, base string, now domain.Time) ([]byte, error) {
	site := siteState{ID: id, Name: name, BaseURL: base, Categories: []category{}, Terms: 1, PublicRevision: 1, MinimumReader: 3}
	b, err := json.Marshal(site)
	if err != nil {
		return nil, err
	}
	op := store.ControlOperation{Schema: 1, Seq: 1, Committed: now, Actor: domain.Actor{Kind: "system", Reason: "bootstrap"}, Mutations: []store.Mutation{{Collection: "site", Key: "state", Value: b}}, Result: store.ControlResult{Code: "initialized", Targets: []string{id.String()}}}
	for i, p := range purposes {
		meta := keyMetadata{ID: uint32(i + 1), Purpose: p, Status: "active", Created: now}
		raw, err := json.Marshal(meta)
		if err != nil {
			return nil, err
		}
		op.Mutations = append(op.Mutations, store.Mutation{Collection: "key_metadata", Key: strconv.Itoa(i + 1), Value: raw})
	}
	raw, err := json.Marshal(op)
	if err != nil {
		return nil, err
	}
	return store.EncodeFrame(store.Frame{FirstSeq: 1, Records: []store.Record{{ID: domain.NewID(), JSON: raw}}})
}
