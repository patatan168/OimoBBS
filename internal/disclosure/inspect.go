// 停止中の検査は案件正本を補完・切詰めず、未知状態や作成途中を報告する。
package disclosure

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Inspect は署名・連鎖・private modeを読み取りだけで検査する。作成途中はErrIncomplete。
func Inspect(root string, key ed25519.PrivateKey) error { return InspectVersion(root, key, 41) }

// InspectVersion はサイトの最低readerとHTTP保全欄の対応も読取りだけで照合する。
func InspectVersion(root string, key ed25519.PrivateKey, reader uint32) error {
	_, e := InspectCasesVersion(root, key, reader)
	return e
}

// InspectCasesVersion は署名履歴/HTTP artifactを変更せず検査し、最新案件metadataを独立所有で返す。
// 作成途中はErrIncomplete。期限到達/closedのmetadataを開示認可として使用しない。
func InspectCasesVersion(root string, key ed25519.PrivateKey, reader uint32) ([]Case, error) {
	return inspectCaseMetadataVersion(root, key, reader, true)
}

// InspectCaseMetadataVersion は署名済み最新metadataを読取り、原本側の復旧前照合へ渡す。
// HTTPコピーの途中状態/本文は検査しない。開示前には通常のInspect/HTTPRecordsを別途要求する。
func InspectCaseMetadataVersion(root string, key ed25519.PrivateKey, reader uint32) ([]Case, error) {
	return inspectCaseMetadataVersion(root, key, reader, false)
}

// inspectCaseMetadataVersion は全履歴の署名/reader/固定範囲を検査し、必要時だけHTTP artifactも検査する。
func inspectCaseMetadataVersion(root string, key ed25519.PrivateKey, reader uint32, artifacts bool) ([]Case, error) {
	inspected, e := inspectRequiredCaseMetadataVersion(root, key, reader, artifacts)
	if e != nil {
		return nil, e
	}
	cases := make([]Case, 0, len(inspected))
	for _, row := range inspected {
		cases = append(cases, row.Current)
	}
	return cases, nil
}

// inspectRequiredCaseMetadataVersion は全履歴を一度だけ走査して現在案件と最初の固定intentを抽出する。
func inspectRequiredCaseMetadataVersion(root string, key ed25519.PrivateKey, reader uint32, artifacts bool) ([]RequiredCaseInspection, error) {
	info, e := os.Lstat(root)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || len(key) != ed25519.PrivateKeySize {
		return nil, store.ErrCorrupt
	}
	s := &Store{root: root, key: key}
	cases := make([]RequiredCaseInspection, 0)
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	if len(entries) > MaxCases*2 {
		return nil, ErrLimit
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".create-") {
			return nil, store.ErrIncomplete
		}
		var id domain.ID
		if !entry.IsDir() || json.Unmarshal([]byte(fmt.Sprintf("%q", entry.Name())), &id) != nil {
			return nil, store.ErrCorrupt
		}
		info, e := entry.Info()
		if e != nil {
			return nil, e
		}
		if info.Mode().Perm() != 0700 {
			return nil, store.ErrCorrupt
		}
		latest, e := s.inspectRequiredCaseHistory(id, reader, artifacts)
		if e != nil {
			return nil, e
		}
		cases = append(cases, latest)
	}
	return cases, nil
}

// inspectRequiredCaseHistory は一案件の既知directoryと全署名履歴を照合し、固定intentを独立所有で返す。
func (s *Store) inspectRequiredCaseHistory(id domain.ID, reader uint32, artifacts bool) (RequiredCaseInspection, error) {
	if e := s.inspectCaseDirectories(id); e != nil {
		return RequiredCaseInspection{}, e
	}
	state, e := store.InspectControl(filepath.Join(s.root, id.String(), "control"), 9, id, 0, s.validator(id))
	if e != nil {
		return RequiredCaseInspection{}, e
	}
	var result RequiredCaseInspection
	e = s.walkHistory(id, state, func(a Audit, _ evidence.Event) error {
		result.Current = a.Case
		if a.Case.RequiredExtension != nil && a.Case.RequiredExtension.State == "complete" {
			result.ConfirmedExtension = a.Case.RequiredExtension
		}
		if result.Intent == nil && a.Action == "hold_intent" && len(a.Case.Items) != 0 {
			result.Intent = &RequiredHoldIntent{Binding: requiredIntentBinding(a.Case, a.Seq), At: a.At, Items: slices.Clone(a.Case.Items), Records: slices.Clone(a.Case.Scope.Records)}
		}
		return inspectCaseAuditReader(a, reader)
	})
	if e != nil {
		return RequiredCaseInspection{}, e
	}
	if artifacts {
		if e = s.inspectHTTPArtifacts(result.Current, false); e != nil {
			return RequiredCaseInspection{}, e
		}
	}
	return result, nil
}

// inspectCaseDirectories は案件直下の既知directoryだけを許可し、未知artifactを変更しない。
func (s *Store) inspectCaseDirectories(id domain.ID) error {
	children, e := os.ReadDir(filepath.Join(s.root, id.String()))
	if e != nil {
		return e
	}
	for _, child := range children {
		if !child.IsDir() {
			return store.ErrCorrupt
		}
		switch child.Name() {
		case "control", "items", "exports", "http":
		default:
			return store.ErrCorrupt
		}
	}
	return nil
}

// inspectCaseReader は署名履歴中のHTTP/元予約欄が最低readerを満たすことを照合する。
func inspectCaseReader(c Case, reader uint32) error {
	if reader < 54 && caseHasRejectedHold(c) {
		return store.ErrCorrupt
	}
	if reader < 53 && caseHasRejectedExports(c) {
		return store.ErrCorrupt
	}
	if uint64(c.Revision) > MaxCaseAudits && reader < 49 {
		return store.ErrCorrupt
	}
	if caseSourceReaderTooLow(c, reader) {
		return store.ErrCorrupt
	}
	if c.HTTP == nil {
		return nil
	}
	return inspectHTTPCaseReader(c.HTTP, reader)
}

// caseSourceReaderTooLow は保存済み元予約/延長の必要reader不足を判定する。
func caseSourceReaderTooLow(c Case, reader uint32) bool {
	return c.RequiredExtension != nil && reader < 47 || c.Required != nil && reader < 46 || c.Extension != nil && reader < 44
}

// inspectHTTPCaseReader はHTTP予約/解除欄への旧reader混在を拒否する。
func inspectHTTPCaseReader(h *HTTPHold, reader uint32) error {
	if h.Unbound && reader < 57 {
		return store.ErrCorrupt
	}
	if reader < 41 || h.Reservation != nil && reader < 42 || h.Released != nil && reader < 43 {
		return store.ErrCorrupt
	}
	return nil
}

// inspectCaseAuditReader はreader50の提出物回収行と旧終端列を区別する。
func inspectCaseAuditReader(a Audit, reader uint32) error {
	if a.Action == "http_query" && reader < 56 {
		return store.ErrCorrupt
	}
	if a.Action == "rejected_query" && reader < 53 {
		return store.ErrCorrupt
	}
	if a.Action == exportCleanupAction && reader < 50 {
		return store.ErrCorrupt
	}
	if uint64(a.Seq) > MaxCaseAudits+caseTerminalAudits && reader < 50 {
		return store.ErrCorrupt
	}
	return inspectCaseReader(a.Case, reader)
}

// caseHasRejectedHold は案件保全と、それを参照する提出物の追加形式を識別する。
func caseHasRejectedHold(c Case) bool {
	if c.Rejected != nil {
		return true
	}
	for _, v := range c.Exports {
		if v.RejectedHeld {
			return true
		}
	}
	return false
}
