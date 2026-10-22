// 初期化完了印を最後に保存し、起動前検査では秘密を返さず永続状態を照合する。
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

var emptyDirectories = []string{"boards", "expiry", "audit", "reports", "jobs", "media", "backups", "tmp", "evidence", "cases"}

// Report はサイト・板管理の検査結果。公開受付readyや全保存データの検証を表さない。
type Report struct {
	Status        string     `json:"status"`
	SiteID        domain.ID  `json:"site_id"`
	SiteName      string     `json:"site_name"`
	SiteSeq       domain.U64 `json:"site_seq"`
	MinimumReader uint32     `json:"minimum_reader_version"`
	KeyCount      int        `json:"key_count"`
	BoardCount    int        `json:"board_count"`
}

// Initialize は未作成のdata dirへ鍵・site control・完了印をSyncして作成する。
// 失敗時に既存物や途中成果を消さない。初期化途中のdirへの再実行は拒否する。
func Initialize(cfg Config, name string) (Report, error) {
	return initialize(cfg, name, func(string) {})
}

// initializeのcheckpointはprocess停止試験用で、公開CLIから指定できない。
func initialize(cfg Config, name string, checkpoint func(string)) (report Report, err error) {
	if err = cfg.validate(); err != nil {
		return report, err
	}
	if !validName(name) {
		return report, errors.New("site name must contain 1..128 non-control characters")
	}
	if err = cfg.checkTLS(time.Now()); err != nil {
		return report, err
	}
	parent := filepath.Dir(cfg.DataDir)
	if err = noSymlinks(parent); err != nil {
		return report, err
	}
	if err = makePrivateDir(cfg.DataDir); err != nil {
		return report, err
	}
	lock, err := platform.Lock(cfg.DataDir)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, platform.Unlock(lock)) }()
	if err = privatePath(cfg.DataDir, true); err != nil {
		return report, err
	}
	for _, dir := range append([]string{"keys"}, emptyDirectories...) {
		if err = makePrivateDir(filepath.Join(cfg.DataDir, dir)); err != nil {
			return report, err
		}
	}
	checkpoint("directory")
	marker, err := generateKeys(cfg.DataDir)
	if err != nil {
		return report, err
	}
	checkpoint("keys")
	marker.SiteID = domain.NewID()
	frame, err := initialFrame(marker.SiteID, name, cfg.Public.BaseURL, domain.Time(time.Now().UnixNano()))
	if err != nil {
		return report, err
	}
	log, err := store.CreateControl(filepath.Join(cfg.DataDir, "site"), store.Header{Kind: 1, Owner: marker.SiteID, Generation: 1}, frame, validateSiteValue)
	if err != nil {
		return report, err
	}
	if err = log.Close(); err != nil {
		return report, err
	}
	checkpoint("site")
	raw, err := json.Marshal(marker)
	if err != nil {
		return report, err
	}
	if err = writeNew(filepath.Join(cfg.DataDir, "instance.json"), append(raw, '\n')); err != nil {
		return report, err
	}
	if err = store.SyncDirectory(cfg.DataDir); err != nil {
		return report, err
	}
	checkpoint("complete")
	return checkLocked(cfg)
}

// Check は全offline操作と同じ排他を取り、初期サイト・鍵・保存形式を変更せず検査する。
func Check(cfg Config) (report Report, err error) {
	if err = cfg.validate(); err != nil {
		return report, err
	}
	if err = cfg.checkTLS(time.Now()); err != nil {
		return report, err
	}
	if err = privatePath(cfg.DataDir, true); err != nil {
		return report, err
	}
	// 検査だけで欠落したロックファイルを新規生成しない。
	if err = privatePath(filepath.Join(cfg.DataDir, ".lock"), false); err != nil {
		return report, err
	}
	lock, err := platform.Lock(cfg.DataDir)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, platform.Unlock(lock)) }()
	return checkLocked(cfg)
}
func checkLocked(cfg Config) (Report, error) { return checkLockedMode(cfg, false) }
func checkLockedMode(cfg Config, allowPending bool) (Report, error) {
	return checkLockedPosting(cfg, allowPending, false)
}

// 投稿対応起動だけは構造検査後に全投稿の照合を行う。通常checkでは未検証データを許可しない。
func checkLockedPosting(cfg Config, allowPending, allowPosting bool) (Report, error) {
	return checkLockedPostingIntent(cfg, allowPending, allowPosting, "")
}

// checkLockedPostingIntent は停止中切替の最終検査だけに既知のintent名を許可する。
func checkLockedPostingIntent(cfg Config, allowPending, allowPosting bool, intent string) (Report, error) {
	var report Report
	rootNames := append([]string{".lock", "instance.json", "keys", "site"}, emptyDirectories...)
	if intent != "" {
		rootNames = append(rootNames, intent)
	}
	reserve, err := inspectEmergencyReserve(cfg.DataDir)
	if err != nil {
		return report, err
	}
	if reserve.Enabled {
		rootNames = append(rootNames, emergencyReserveName)
	}
	if err := requireEntries(cfg.DataDir, rootNames); err != nil {
		return report, err
	}
	if err := requireEntries(filepath.Join(cfg.DataDir, "keys"), []string{"master-000001.key", "evidence-000010.seed"}); err != nil {
		return report, err
	}
	for _, dir := range emptyDirectories {
		if dir == "boards" || dir == "jobs" || dir == "audit" || dir == "cases" || dir == "reports" || allowPosting && (dir == "evidence" || dir == "expiry") {
			continue
		}
		if err := requireEmpty(filepath.Join(cfg.DataDir, dir)); err != nil {
			return report, err
		}
	}
	b, err := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if err != nil {
		return report, err
	}
	var marker instance
	if err = strictjson.Decode(b, &marker); err != nil {
		return report, err
	}
	if marker.Schema != storageFormatVersion {
		return report, errors.New("unsupported instance format")
	}
	if err = checkKeys(cfg.DataDir, marker); err != nil {
		return report, err
	}
	state, err := inspectRuntimeControl(cfg.DataDir, "site", marker.SiteID)
	if err != nil {
		return report, err
	}
	site, err := inspectSiteState(state, marker.SiteID, cfg.Public.BaseURL)
	if err != nil {
		return report, err
	}
	if err = inspectCaseRetirementRegistry(state, site, ed25519.PublicKey(marker.SigningPublic[:]), domain.Time(time.Now().UnixNano())); err != nil {
		return report, err
	}
	if !allowPending {
		if err = inspectRegisteredCaseRetirementFiles(cfg.DataDir, state); err != nil {
			return report, err
		}
	}
	m, err := store.InspectControlManifest(filepath.Join(cfg.DataDir, "site"))
	if err != nil {
		return report, err
	}
	if m.Snapshot != nil && site.MinimumReader < 12 {
		return report, errors.New("snapshot requires reader version 12")
	}
	if err = inspectAudit(cfg, state, site.MinimumReader, allowPending); err != nil {
		return report, err
	}
	boards, err := inspectBoardsMode(cfg, state, allowPending, allowPosting)
	if err != nil {
		return report, err
	}
	if err = inspectDeletionOwners(cfg, site, boards, allowPosting); err != nil {
		return report, err
	}
	if err = inspectRequiredGCJobScope(cfg, state, site, boards, ed25519.PublicKey(marker.SigningPublic[:])); err != nil {
		return report, err
	}
	if allowPosting {
		if err = inspectRequiredPostingJournals(cfg, site, boards); err != nil {
			return report, err
		}
	}
	if allowPending {
		if err = resumeOptionalHoldRetirementsAt(cfg, site, state, time.Now()); err != nil {
			return report, err
		}
		if err = resumeRegisteredCaseRetirements(cfg, site, state); err != nil {
			return report, err
		}
	}
	if err = inspectRequiredHoldStorage(cfg, site, state, allowPending); err != nil {
		return report, err
	}
	if err = inspectReports(cfg, site, state, allowPending); err != nil {
		return report, err
	}
	if err = inspectOptionalLogs(cfg, site, state, allowPending); err != nil {
		return report, err
	}
	if err = inspectEvidenceCases(cfg.DataDir, site.MinimumReader, allowPending, state); err != nil {
		return report, err
	}
	report = Report{BoardCount: len(boards), Status: "bootstrap_valid", SiteID: site.ID, SiteName: site.Name, SiteSeq: state.Seq, MinimumReader: site.MinimumReader, KeyCount: len(purposes)}
	return report, nil
}

// inspectSiteState はWALとsnapshotで共通の必須行・所有者・版・期限を検査する。
func inspectSiteState(state store.ControlState, owner domain.ID, baseURL string) (siteState, error) {
	row, ok := state.Rows["site:state"]
	dirs, err := siteDirectories(state)
	if err != nil {
		return siteState{}, err
	}
	_, hasRate := state.Rows["rate_policy:active"]
	extra := 0
	if hasRate {
		extra = 1
	}
	if _, exists := state.Rows[postingResourcesCollection+":active"]; exists {
		extra++
	}
	_, hasAnon := state.Rows["anon_policy:active"]
	if hasAnon {
		extra++
	}
	_, hasNetworks := state.Rows["network:active"]
	if hasNetworks {
		extra++
	}
	_, hasSlip := state.Rows["slip_policy:active"]
	if hasSlip {
		extra++
	}
	hasAdmin := false
	hasPasskeys := false
	activeSiteAdmins := 0
	extendedAdminAccess := false
	for name, adminRow := range state.Rows {
		if strings.HasPrefix(name, "admin_security:") {
			var security adminSecurityState
			var securitySite siteState
			if strictjson.Decode(state.Rows["site:state"].Value, &securitySite) != nil || securitySite.MinimumReader < adminSecurityReader {
				return siteState{}, store.ErrCorrupt
			}
			if adminRow.Expires != nil || strictjson.Decode(adminRow.Value, &security) != nil {
				return siteState{}, errors.New("invalid administrator security state")
			}
			if _, ok := state.Rows["administrator:"+security.Admin.String()]; !ok {
				return siteState{}, errors.New("administrator security owner missing")
			}
			var keys adminPasskeySet
			if row, ok := state.Rows["admin_passkeys:"+security.Admin.String()]; ok {
				if strictjson.Decode(row.Value, &keys) != nil {
					return siteState{}, store.ErrCorrupt
				}
			}
			if security.PasswordChangeRequired && len(keys.Keys) > 0 {
				return siteState{}, store.ErrCorrupt
			}
			if security.PasswordDisabled && len(security.OTPSealed) == 0 && len(keys.Keys) == 0 {
				return siteState{}, errors.New("administrator has no permitted authenticator")
			}
			extra++
		}
		if strings.HasPrefix(name, "admin_passkeys:") {
			var keys adminPasskeySet
			if adminRow.Expires != nil || strictjson.Decode(adminRow.Value, &keys) != nil {
				return siteState{}, errors.New("invalid administrator passkey state")
			}
			if _, ok := state.Rows["administrator:"+keys.Admin.String()]; !ok {
				return siteState{}, errors.New("passkey owner missing")
			}
			extra++
			hasPasskeys = true
		}
		if strings.HasPrefix(name, "administrator:") {
			hasAdmin = true
			var admin administrator
			if e := strictjson.Decode(adminRow.Value, &admin); e != nil {
				return siteState{}, e
			}
			if admin.Role == "site_admin" && admin.Enabled {
				activeSiteAdmins++
			}
			if admin.Role != "site_admin" || len(admin.Permissions) != 0 {
				extendedAdminAccess = true
			}
			for _, id := range admin.Boards {
				if _, ok := dirs[id]; !ok {
					return siteState{}, errors.New("administrator board scope missing")
				}
			}
			extra++
		}
	}
	caps, e := loadCapRegistry(state)
	if e != nil {
		return siteState{}, e
	}
	for _, cap := range caps.Records {
		for _, id := range cap.Boards {
			if dirs[id] == nil || dirs[id].Status != "active" {
				return siteState{}, errors.New("cap board scope missing")
			}
		}
	}
	revocations := uint32(0)
	for name := range state.Rows {
		if strings.HasPrefix(name, optionalHoldRetirementCollection+":") {
			extra++
		}
		if strings.HasPrefix(name, "case_retirement:") {
			extra++
		}
		if name == "report_store:active" {
			extra++
		}
		if name == "required_gc:originals" {
			extra++
		}
		if strings.HasPrefix(name, "cap:") {
			extra++
		}
		if strings.HasPrefix(name, "required_holds:") {
			extra++
		}
		if name == "optional_http:http" || name == "optional_loss:http" || name == "optional_holds:http" {
			extra++
		}
		if name == "expiry_watermark:control" {
			extra++
		}
		if strings.HasPrefix(name, "posting_violation:") {
			if !hasRate || !hasAnon {
				return siteState{}, store.ErrCorrupt
			}
			extra++
		}
		if name == "abuse_guard:active" || strings.HasPrefix(name, "abuse_guard_receipt:") || strings.HasPrefix(name, "global_posting_policy:") {
			if !hasAdmin || !hasRate || !hasAnon {
				return siteState{}, store.ErrCorrupt
			}
			extra++
		}
		if strings.HasPrefix(name, "reading_access:") {
			if !hasAdmin {
				return siteState{}, store.ErrCorrupt
			}
			scope := strings.TrimPrefix(name, "reading_access:")
			id, err := readingScope(scope)
			if err != nil || id != (domain.ID{}) && dirs[id] == nil {
				return siteState{}, store.ErrCorrupt
			}
			extra++
		}
		if strings.HasPrefix(name, "waf:") {
			if name != "waf:active" || !hasAdmin {
				return siteState{}, store.ErrCorrupt
			}
			extra++
		}
		if name == "operations:active" || strings.HasPrefix(name, "operations_receipt:") {
			if !hasAdmin {
				return siteState{}, store.ErrCorrupt
			}
			extra++
		}
		if strings.HasPrefix(name, "admin_receipt:") {
			if !hasAdmin {
				return siteState{}, errors.New("admin receipt without administrator")
			}
			extra++
		}
		if strings.HasPrefix(name, "token_revocation:") {
			revocations++
		}
		if strings.HasPrefix(name, "token_issue:") || strings.HasPrefix(name, "token_revocation:") || strings.HasPrefix(name, "token_reissue:") {
			if !hasAnon {
				return siteState{}, errors.New("anonymous record without policy")
			}
			extra++
		}
	}
	if !ok || len(state.Rows) != 1+len(purposes)+len(dirs)+extra {
		return siteState{}, errors.New("required site objects are missing")
	}
	var site siteState
	if err := strictjson.Decode(row.Value, &site); err != nil {
		return siteState{}, err
	}
	for name, reading := range state.Rows {
		if strings.HasPrefix(name, "reading_access:") && (site.MinimumReader < readingMinimumReader(reading.Value) || reading.Expires != nil || validateReadingValue(strings.TrimPrefix(name, "reading_access:"), reading.Value) != nil) {
			return siteState{}, store.ErrCorrupt
		}
	}
	if hasSlip {
		var policy slipPolicy
		p, err := decodeAnonymous(state.Rows["anon_policy:active"].Value)
		activation := state.Rows["slip_policy:active"]
		if !hasAnon || !hasRate || site.MinimumReader < 70 || activation.Expires != nil || strictjson.Decode(activation.Value, &policy) != nil || p.Mode != "required" || p.Schema != "anon-policy-v4" || err != nil || policy.Activated < p.Enabled || policy.Activated > domain.Time(time.Now().UnixNano()) {
			return siteState{}, store.ErrCorrupt
		}
	}
	if err := inspectGuardState(state, site); err != nil {
		return siteState{}, err
	}
	if row, present := state.Rows["waf:active"]; present && site.MinimumReader < wafMinimumReader(row.Value) {
		return siteState{}, store.ErrCorrupt
	}
	if _, present := state.Rows["operations:active"]; present && site.MinimumReader < 69 {
		return siteState{}, store.ErrCorrupt
	}
	if row, present := state.Rows["operations:active"]; present {
		var operation operationState
		if strictjson.Decode(row.Value, &operation) != nil {
			return siteState{}, store.ErrCorrupt
		}
		v := operation.Settings
		if v.ReportIntervalMinutes != 0 && site.MinimumReader < reportIntervalReader {
			return siteState{}, store.ErrCorrupt
		}
		if v.EgressBits > 1_000_000_000 && site.MinimumReader < postingResourcesReader {
			return siteState{}, store.ErrCorrupt
		}
		if (v.CacheWorkers == 0 || v.CacheWorkers > 8 || v.CacheBytes > 128<<20) && site.MinimumReader < 89 {
			return siteState{}, store.ErrCorrupt
		}
	}
	if _, e := caseRetirementRegistrations(state, site); e != nil {
		return siteState{}, e
	}
	if _, e := optionalHoldRetirementRegistrations(state, site); e != nil {
		return siteState{}, e
	}
	if _, e := requiredHoldActivations(state, site); e != nil {
		return siteState{}, e
	}
	if _, e := readRequiredGCState(state, site, domain.Time(time.Now().UnixNano())); e != nil {
		return siteState{}, e
	}
	if activation, ok := state.Rows["report_store:active"]; ok {
		var v optionalLogActivation
		if activation.Expires != nil || strictjson.Decode(activation.Value, &v) != nil || v.Site != site.ID || site.MinimumReader < 62 {
			return siteState{}, store.ErrCorrupt
		}
	}
	if activation, ok := state.Rows["optional_http:http"]; ok {
		var v optionalLogActivation
		if strictjson.Decode(activation.Value, &v) != nil || v.Site != site.ID || site.MinimumReader < 39 {
			return siteState{}, store.ErrCorrupt
		}
	}
	if activation, ok := state.Rows["optional_loss:http"]; ok {
		var v optionalLogActivation
		if strictjson.Decode(activation.Value, &v) != nil || v.Site != site.ID || site.MinimumReader < 40 {
			return siteState{}, store.ErrCorrupt
		}
		if _, exists := state.Rows["optional_http:http"]; !exists {
			return siteState{}, store.ErrCorrupt
		}
	}
	if activation, ok := state.Rows["optional_holds:http"]; ok {
		var v optionalLogActivation
		if strictjson.Decode(activation.Value, &v) != nil || v.Schema != optionalHoldActivationSchema || v.Site != site.ID || site.MinimumReader < 42 {
			return siteState{}, store.ErrCorrupt
		}
		parent, exists := state.Rows["optional_http:http"]
		var source optionalLogActivation
		if !exists || strictjson.Decode(parent.Value, &source) != nil || source.Phase != "active" {
			return siteState{}, store.ErrCorrupt
		}
	}
	if hasNetworks {
		if site.MinimumReader < 30 || !hasAdmin && site.MinimumReader < 81 {
			return siteState{}, store.ErrCorrupt
		}
		network, e := loadNetworkState(state)
		if e != nil {
			return siteState{}, e
		}
		if (networkRequiresSpecialReader(network) || networkStatePacked92(state.Rows["network:active"].Value)) && site.MinimumReader < specialNetworkReader {
			return siteState{}, store.ErrCorrupt
		}
		if networkRequiresMixedReader(network) && site.MinimumReader < mixedNetworkReader {
			return siteState{}, store.ErrCorrupt
		}
		if (networkRequiresReader81(network) || networkRowsPacked(state.Rows["network:active"].Value)) && site.MinimumReader < 81 {
			return siteState{}, store.ErrCorrupt
		}
		if network.Config.DNSMode != "" && site.MinimumReader < 37 {
			return siteState{}, store.ErrCorrupt
		}
		if networkRequiresCountryConflictsReader(network) && site.MinimumReader < countryConflictsReader {
			return siteState{}, store.ErrCorrupt
		}
		if networkRequiresReader33(network) && site.MinimumReader < 33 {
			return siteState{}, store.ErrCorrupt
		}
		if networkRequiresReader32(network) && site.MinimumReader < 32 {
			return siteState{}, store.ErrCorrupt
		}
		for _, category := range network.Config.Categories {
			if category.Description != "" && site.MinimumReader < 31 {
				return siteState{}, store.ErrCorrupt
			}
		}
	}
	if hasPasskeys && site.MinimumReader < 94 {
		return siteState{}, errors.New("passkeys require reader 94")
	}
	if hasAdmin && activeSiteAdmins == 0 || extendedAdminAccess && site.MinimumReader < 15 {
		return siteState{}, errors.New("administrator access requires an active site administrator and reader 15")
	}
	for _, cap := range caps.Records {
		if (cap.Expires == 0 || cap.Expires-cap.Created > 180*86400e9) && site.MinimumReader < 35 {
			return siteState{}, store.ErrCorrupt
		}
	}
	if len(caps.Records) > 0 && (!hasAdmin || site.MinimumReader < 22) {
		return siteState{}, errors.New("caps require administrators and reader 22")
	}
	if site.ID != owner || site.BaseURL != baseURL || site.PublicRevision > row.Revision {
		return siteState{}, errors.New("site identity, base URL, or public revision mismatch")
	}
	expectedReader := uint32(3)
	if hasRate {
		expectedReader = 4
	}
	if hasAnon {
		expectedReader = 5
	}
	if hasAdmin {
		expectedReader = 6
	}
	if !validAdmissionReader(site.MinimumReader, expectedReader, hasAdmin) || hasAnon && !hasRate {
		return siteState{}, errors.New("admission reader version mismatch")
	}
	if watermark, ok := state.Rows["expiry_watermark:control"]; ok {
		var floor controlExpiryWatermark
		if e := strictjson.Decode(watermark.Value, &floor); e != nil {
			return siteState{}, e
		}
		if site.MinimumReader < 21 || floor.At > domain.Time(time.Now().UnixNano()) {
			return siteState{}, errors.New("control expiry requires reader 21 and a non-regressed clock")
		}
	}
	if hasAnon {
		_, e := decodeAnonymous(state.Rows["anon_policy:active"].Value)
		if e != nil || site.MinimumReader < 70 {
			return siteState{}, store.ErrCorrupt
		}
	}
	if _, exists := state.Rows[postingResourcesCollection+":active"]; exists && site.MinimumReader < postingResourcesReader {
		return siteState{}, store.ErrCorrupt
	}
	if hasRate {
		policy, e := validateAdmission(state.Rows["rate_policy:active"].Value)
		if e != nil || policy.Schema == "admission-v3" && site.MinimumReader < 19 {
			return siteState{}, errors.New("online admission requires reader 19")
		}
	}
	for key, row := range state.Rows {
		if strings.HasPrefix(key, "admin_receipt:") && isCapReceipt(row.Value) {
			var receipt capReceipt
			if strictjson.Decode(row.Value, &receipt) != nil {
				return siteState{}, store.ErrCorrupt
			}
			current, ok := caps.Records[receipt.Result.ID]
			if !ok || site.MinimumReader < 22 || receipt.Result.Revision > current.Revision || receipt.Result.Name != current.Name || receipt.Result.Expires != current.Expires || !reflect.DeepEqual(receipt.Result.Boards, current.Boards) || !reflect.DeepEqual(receipt.Result.Permissions, current.Permissions) {
				return siteState{}, store.ErrCorrupt
			}
		}
		if strings.HasPrefix(key, "admin_receipt:") && isAnonymousReceipt(row.Value) {
			var receipt anonymousReceipt
			if e := strictjson.Decode(row.Value, &receipt); e != nil {
				return siteState{}, e
			}
			policy, e := decodeAnonymous(state.Rows["anon_policy:active"].Value)
			if e != nil || site.MinimumReader < 18 || !anonymousReceiptModeMatches(policy, receipt) || receipt.Result.Generation > policy.Generation || receipt.Result.Revocations > revocations || receipt.Result.Revision > state.Rows["anon_policy:active"].Revision {
				return siteState{}, errors.New("anonymous receipt boundary mismatch")
			}
		}
		if strings.HasPrefix(key, "admin_receipt:") && isAccountReceipt(row.Value) && site.MinimumReader < 17 {
			return siteState{}, errors.New("administrator change receipt requires reader 17")
		}
		if strings.HasPrefix(key, "admin_receipt:") && isNetworkReceipt(row.Value) {
			var receipt networkReceipt
			network, e := loadNetworkState(state)
			if e != nil || strictjson.Decode(row.Value, &receipt) != nil || !hasNetworks || site.MinimumReader < 30 || receipt.Version > network.Version {
				return siteState{}, store.ErrCorrupt
			}
		}
		if row.Expires != nil {
			return siteState{}, fmt.Errorf("required site object has an expiry: %s", key)
		}
	}
	for i := range purposes {
		if _, ok := state.Rows["key_metadata:"+strconv.Itoa(i+1)]; !ok {
			return siteState{}, errors.New("required key metadata is missing")
		}
	}
	if _, err := inspectViolations(state, site); err != nil {
		return siteState{}, err
	}
	return site, nil
}

// generateKeys は乱数masterと独立したEd25519 seedを0600で保存する。
func generateKeys(dir string) (instance, error) {
	marker := instance{Schema: storageFormatVersion}
	master := make([]byte, 32)
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(master)
	_, _ = rand.Read(seed)
	defer clear(master)
	defer clear(seed)
	if err := writeNew(filepath.Join(dir, "keys", "master-000001.key"), master); err != nil {
		return marker, err
	}
	if err := writeNew(filepath.Join(dir, "keys", "evidence-000010.seed"), seed); err != nil {
		return marker, err
	}
	if err := store.SyncDirectory(filepath.Join(dir, "keys")); err != nil {
		return marker, err
	}
	marker.MasterSHA = sha256.Sum256(master)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	copy(marker.SigningPublic[:], private.Public().(ed25519.PublicKey))
	return marker, nil
}
func checkKeys(dir string, marker instance) error {
	master, err := readPrivate(filepath.Join(dir, "keys", "master-000001.key"), 32)
	if err != nil {
		return err
	}
	defer clear(master)
	if len(master) != 32 || sha256.Sum256(master) != marker.MasterSHA {
		return errors.New("master key does not match instance")
	}
	// 用途とIDの両方をLP符号化に含める。鍵の生値を検査結果へ返さない。
	seen := map[domain.Hash]bool{}
	for i, p := range purposes[:len(purposes)-1] {
		key, err := identity.DeriveKey(master, p, uint32(i+1))
		if err != nil {
			return err
		}
		if seen[key] {
			return errors.New("duplicate derived key")
		}
		seen[key] = true
	}
	seed, err := readPrivate(filepath.Join(dir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if err != nil {
		return err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return errors.New("invalid evidence signing seed")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), marker.SigningPublic[:]) {
		return errors.New("evidence signing key does not match instance")
	}
	return nil
}
func requireEntries(dir string, names []string) error {
	if err := privatePath(dir, true); err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, name := range names {
		expected[name] = true
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := f.Readdirnames(len(names) + 1)
	if err != nil {
		return err
	}
	if len(entries) != len(names) {
		return fmt.Errorf("unexpected or missing entries: %s", dir)
	}
	for _, name := range entries {
		if !expected[name] {
			return fmt.Errorf("unsupported entry in %s", dir)
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if err = privatePath(path, info.IsDir()); err != nil {
			return err
		}
	}
	return nil
}

// validAdmissionReader は初期機能の版対応と、後続追加形式の既知reader範囲を照合する。
// validAdmissionReader は新規形式の機能宣言を下限として検査し、旧版別の例外を持たない。
func validAdmissionReader(actual, expected uint32, _ bool) bool {
	return actual >= expected && actual <= readerVersion
}
