// 非公開依頼を署名付きの有界私有fileへ保存し、理由・連絡先をWALや公開DTOへ残さない。
package bootstrap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const reportDirectory = "requests"
const reportLimit = 1024

type deletionReport struct {
	Automatic  *automaticReportReceipt `json:"automatic"`
	ID         domain.ID               `json:"id"`
	Board      domain.ID               `json:"board_id"`
	Thread     domain.U64              `json:"thread_key"`
	Ranges     string                  `json:"ranges"`
	Category   string                  `json:"category"`
	Reason     string                  `json:"reason"`
	Contact    string                  `json:"contact"`
	SourceIP   string                  `json:"source_ip"`
	LookupHash domain.Hash             `json:"lookup_secret_hash"`
	State      string                  `json:"state"`
	Assignee   *domain.ID              `json:"assignee_id"`
	Answer     string                  `json:"answer"`
	Duplicate  *domain.ID              `json:"duplicate_of"`
	Created    domain.Time             `json:"created_at_ns"`
	Resolved   *domain.Time            `json:"resolved_at_ns"`
	Expires    domain.Time             `json:"expires_at_ns"`
	Updated    domain.Time             `json:"updated_at_ns"`
	Revision   uint64                  `json:"revision"`
}

type reportEnvelope struct {
	Value deletionReport `json:"value"`
	MAC   domain.Hash    `json:"mac"`
}

func reportKey(root string) ([32]byte, error) {
	master, e := readPrivate(filepath.Join(root, "keys", "master-000001.key"), 32)
	if e != nil {
		return [32]byte{}, e
	}
	defer clear(master)
	return identity.DeriveKey(master, "csrf", 6)
}

// validateReport は固定種別・私情報の文字数・終端後も延ばさない期限を検査する。
func validateReport(v deletionReport) error {
	if err := validateAutomaticReportReceipt(v.Automatic, v); err != nil {
		return err
	}
	ip, e := netip.ParseAddr(v.SourceIP)
	if e != nil || ip.Zone() != "" || ip.Unmap().String() != v.SourceIP || ip.IsUnspecified() || v.ID == (domain.ID{}) || v.Board == (domain.ID{}) || v.Thread == 0 || v.LookupHash == (domain.Hash{}) || v.Revision == 0 {
		return store.ErrCorrupt
	}
	if !slices.Contains([]string{"normal", "important", "inquiry"}, v.Category) || !slices.Contains([]string{"open", "in_progress", "resolved", "rejected", "duplicate"}, v.State) || !reportText(v.Reason, 4000) || strings.TrimSpace(v.Reason) == "" || !reportText(v.Contact, 512) || !reportText(v.Answer, 4000) || !validReportRanges(v.Ranges) {
		return store.ErrCorrupt
	}
	if v.Created <= 0 || v.Created > domain.Time(1<<63-1)-180*86400e9 || v.Updated < v.Created || v.Expires <= v.Created || v.Expires > v.Created+180*86400e9 {
		return store.ErrCorrupt
	}
	terminal := slices.Contains([]string{"resolved", "rejected", "duplicate"}, v.State)
	if terminal && v.Resolved == nil || v.Resolved != nil && (*v.Resolved < v.Created || *v.Resolved > v.Updated || v.Expires > *v.Resolved+30*86400e9) {
		return store.ErrCorrupt
	}
	if (v.State == "duplicate") != (v.Duplicate != nil) || v.Duplicate != nil && (*v.Duplicate == v.ID || *v.Duplicate == (domain.ID{})) || v.Assignee != nil && *v.Assignee == (domain.ID{}) {
		return store.ErrCorrupt
	}
	return nil
}
func reportText(s string, limit int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= limit && !strings.ContainsRune(s, 0)
}

// validReportRanges は昇順かつ重複しない最大32範囲の正規十進表記だけを許可する。
func validReportRanges(raw string) bool {
	if raw == "" || len(raw) > 512 {
		return false
	}
	previous := uint64(0)
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		return false
	}
	for _, part := range parts {
		ends := strings.Split(part, "-")
		if len(ends) > 2 {
			return false
		}
		first, e := strconv.ParseUint(ends[0], 10, 32)
		if e != nil || first <= previous || strconv.FormatUint(first, 10) != ends[0] {
			return false
		}
		last := first
		if len(ends) == 2 {
			last, e = strconv.ParseUint(ends[1], 10, 32)
			if e != nil || last <= first || strconv.FormatUint(last, 10) != ends[1] {
				return false
			}
		}
		previous = last
	}
	return true
}

// readReport は私有fileの完全型と用途分離HMACを照合してから依頼を返す。
func readReport(root string, id domain.ID, key [32]byte) (deletionReport, error) {
	raw, e := readPrivate(filepath.Join(root, "reports", reportDirectory, id.String()+".json"), 64<<10)
	if e != nil {
		return deletionReport{}, e
	}
	var envelope reportEnvelope
	if strictjson.Decode(raw, &envelope) != nil || envelope.Value.ID != id || validateReport(envelope.Value) != nil {
		return deletionReport{}, store.ErrCorrupt
	}
	value, e := json.Marshal(envelope.Value)
	if e != nil {
		return deletionReport{}, e
	}
	expected := identity.MAC(key[:], "oimo/report/v1", value)
	if !hmac.Equal(expected[:], envelope.MAC[:]) {
		return deletionReport{}, store.ErrCorrupt
	}
	return envelope.Value, nil
}

// writeReport は一つのfileを置換し、Sync失敗時は書込所有者を停止する責務を呼出元へ返す。
func writeReport(root string, v deletionReport, key [32]byte) error {
	if e := validateReport(v); e != nil {
		return e
	}
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	envelope := reportEnvelope{v, identity.MAC(key[:], "oimo/report/v1", raw)}
	raw, e = json.Marshal(envelope)
	if e != nil {
		return e
	}
	parent := filepath.Join(root, "reports", reportDirectory)
	pending := filepath.Join(parent, v.ID.String()+".pending")
	if e = writeNew(pending, raw); e != nil {
		return e
	}
	if e = os.Rename(pending, filepath.Join(parent, v.ID.String()+".json")); e != nil {
		return e
	}
	return store.SyncDirectory(parent)
}

// reportFiles は最大1024件の確定fileを列挙し、未確定候補は正本に数えない。
func reportFiles(root string) ([]domain.ID, error) {
	parent := filepath.Join(root, "reports", reportDirectory)
	if e := privatePath(parent, true); e != nil {
		return nil, e
	}
	directory, e := os.Open(parent)
	if e != nil {
		return nil, e
	}
	entries, readErr := directory.ReadDir(2*reportLimit + 1)
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	e = errors.Join(readErr, directory.Close())
	if e != nil || len(entries) > 2*reportLimit {
		return nil, store.ErrCorrupt
	}
	result := []domain.ID{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".pending") {
			return nil, store.ErrCorrupt
		}
		id, e := parseReportID(strings.TrimSuffix(strings.TrimSuffix(name, ".json"), ".pending"))
		if e != nil || privatePath(filepath.Join(parent, name), false) != nil {
			return nil, store.ErrCorrupt
		}
		if strings.HasSuffix(name, ".json") {
			result = append(result, id)
		}
	}
	if len(result) > reportLimit {
		return nil, store.ErrCorrupt
	}
	return result, nil
}
func parseReportID(raw string) (domain.ID, error) {
	var id domain.ID
	if id.UnmarshalJSON([]byte(strconv.Quote(raw))) != nil || id == (domain.ID{}) {
		return id, store.ErrCorrupt
	}
	return id, nil
}

// validateReportActivation は所有サイトを固定し、準備から有効化と有効状態の監査更新だけを許す。
func validateReportActivation(key string, old, next json.RawMessage) error {
	var a optionalLogActivation
	if key != "active" || strictjson.Decode(next, &a) != nil || a.Schema != "reports-activation-v1" || a.Site == (domain.ID{}) || a.Phase != "preparing" && a.Phase != "active" {
		return store.ErrCorrupt
	}
	if len(old) == 0 {
		if a.Phase != "preparing" {
			return store.ErrCorrupt
		}
		return nil
	}
	var p optionalLogActivation
	if strictjson.Decode(old, &p) != nil || p.Site != a.Site || p.Schema != a.Schema || p.Phase == "active" && a.Phase != "active" {
		return store.ErrCorrupt
	}
	return nil
}

// inspectReports は起動/checkで署名と有界保存を検査する。途中置換fileは正本に採用しない。
func inspectReports(cfg Config, site siteState, state store.ControlState, allowPending bool) error {
	row, enabled := state.Rows["report_store:active"]
	if !enabled {
		return nil
	}
	var a optionalLogActivation
	if strictjson.Decode(row.Value, &a) != nil || a.Site != site.ID || site.MinimumReader < 62 {
		return store.ErrCorrupt
	}
	parent := filepath.Join(cfg.DataDir, "reports", reportDirectory)
	if _, e := os.Lstat(parent); errors.Is(e, os.ErrNotExist) && a.Phase == "preparing" && allowPending {
		return nil
	}
	if a.Phase != "active" && !allowPending {
		return store.ErrCorrupt
	}
	key, e := reportKey(cfg.DataDir)
	if e != nil {
		return e
	}
	defer clear(key[:])
	ids, e := reportFiles(cfg.DataDir)
	if e != nil {
		return e
	}
	for _, id := range ids {
		if v, e := readReport(cfg.DataDir, id, key); e != nil {
			return e
		} else if v.Automatic != nil && site.MinimumReader < 66 {
			return store.ErrCorrupt
		}
	}
	return nil
}

// ensureReports は先行intentに従って私有directoryを完成させる。空台帳を復旧時に捏造しない。
func (r *Repository) ensureReports() error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	row, enabled := r.site.State().Rows["report_store:active"]
	a := optionalLogActivation{Schema: "reports-activation-v1", Site: site.ID, Phase: "preparing"}
	if enabled {
		if e := strictjson.Decode(row.Value, &a); e != nil {
			return e
		}
	} else {
		site.MinimumReader = max(site.MinimumReader, 62)
		if e := appendControl(r.site, "reports_prepare", []store.Mutation{mutation("site", "state", site, nil), mutation("report_store", "active", a, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
	}
	parent := filepath.Join(r.cfg.DataDir, "reports", reportDirectory)
	if a.Phase == "preparing" {
		if e := os.Mkdir(parent, 0700); e != nil && !os.IsExist(e) {
			return e
		}
		if e := privatePath(parent, true); e != nil {
			return e
		}
		if e := store.SyncDirectory(filepath.Dir(parent)); e != nil {
			return e
		}
		a.Phase = "active"
		if e := appendControl(r.site, "reports_enable", []store.Mutation{mutation("report_store", "active", a, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
	}
	return nil
}

// sweepReports は既存の毎分保守へ接続し、期限を過ぎた私情報のfileを最大128件消す。
func (r *Repository) sweepReports(now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	if _, enabled := r.site.State().Rows["report_store:active"]; !enabled {
		return nil
	}
	if now.UnixNano() < r.controlExpiryFloor.Load() {
		return ErrControlExpiryClock
	}
	if e := r.ensureReports(); e != nil {
		return e
	}
	key, e := reportKey(r.cfg.DataDir)
	if e != nil {
		return e
	}
	defer clear(key[:])
	r.reportMu.Lock()
	defer r.reportMu.Unlock()
	ids, e := reportFiles(r.cfg.DataDir)
	if e != nil {
		return e
	}
	expired := []domain.ID{}
	for _, id := range ids {
		v, e := readReport(r.cfg.DataDir, id, key)
		if e != nil {
			return e
		}
		if v.Expires <= domain.Time(now.UnixNano()) && len(expired) < 128 {
			expired = append(expired, id)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	if now.UnixNano() > r.controlExpiryFloor.Load() {
		if e := appendControlAt(r.site, domain.Time(now.UnixNano()), "reports_expiry", []store.Mutation{mutation("expiry_watermark", "control", controlExpiryWatermark{domain.Time(now.UnixNano())}, nil)}); e != nil {
			r.stopped = true
			return e
		}
		r.controlExpiryFloor.Store(now.UnixNano())
	}
	parent := filepath.Join(r.cfg.DataDir, "reports", reportDirectory)
	for _, id := range expired {
		if e := os.Remove(filepath.Join(parent, id.String()+".json")); e != nil {
			return e
		}
	}
	return store.SyncDirectory(parent)
}

func reportSecretMatches(v deletionReport, raw string) bool {
	digest := sha256.Sum256([]byte(raw))
	return hmac.Equal(v.LookupHash[:], digest[:]) && len(raw) == 43
}
