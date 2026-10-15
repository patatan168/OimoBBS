// 原本回収前の横断照合へ、署名履歴の最初の固定intentと最新案件を非変更で渡す。
package disclosure

import (
	"crypto/ed25519"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"slices"
)

// RequiredHoldIntent は最初の署名済み固定対象。copy本文や接続情報を含めない。
type RequiredHoldIntent struct {
	Binding app.RequiredHoldBinding
	At      domain.Time
	Items   []Item
	Records []domain.ID
}

// RequiredCaseInspection は全署名/reader/連鎖を照合した最新案件と最初の固定intent。
// 開示認可やcopyの物理存在証明としては使用しない。
type RequiredCaseInspection struct {
	Current Case
	Intent  *RequiredHoldIntent
	// ConfirmedExtension は直前の確認済み延長。次のintent待ちでも元承認の照合に使う。
	ConfirmedExtension *RequiredHoldExtension
}

// InspectRequiredCaseMetadataVersion は作成/回収を再開せず、全案件の固定intentを読取り検査する。
// 元予約のOpen/GCより先に使用する。HTTP artifact/copy本文の検査は別途必要。
func InspectRequiredCaseMetadataVersion(root string, key ed25519.PrivateKey, reader uint32) ([]RequiredCaseInspection, error) {
	return inspectRequiredCaseMetadataVersion(root, key, reader, false)
}

func requiredIntentBinding(c Case, revision domain.U64) app.RequiredHoldBinding {
	return app.RequiredHoldBinding{Case: c.ID, Revision: revision, Board: c.Scope.Board, Thread: c.Scope.Thread, From: c.Scope.From, To: c.Scope.To, Until: c.Until}
}

// CheckRequiredCaseReservation は照合済み案件/現在元metadataの固定intent・全対象・解除状態を検査する。
// 引数の元署名/現在性は元所有者が別途検証し、完成copyは解除/GC前に物理照合する。
func CheckRequiredCaseReservation(row RequiredCaseInspection, receipt app.RequiredHoldReceipt) error {
	if row.Current.RequiredExtension != nil {
		return store.ErrIncomplete
	}
	return checkRequiredCaseReservationMetadata(row, receipt)
}

// checkRequiredCaseReservationMetadata は延長承認照合後にも共通の固定対象と解除状態を検査する。
func checkRequiredCaseReservationMetadata(row RequiredCaseInspection, receipt app.RequiredHoldReceipt) error {
	if e := app.ValidateRequiredHoldReceipt(receipt); e != nil {
		return e
	}
	if e := checkRequiredInspectedIntent(row, receipt); e != nil {
		return e
	}
	c := row.Current
	if c.Required == nil {
		return checkRequiredUnreflectedReservation(c, receipt)
	}
	if !sameRequiredReservationIdentity(c.Required.Reservation, receipt) {
		return store.ErrCorrupt
	}
	if c.Required.Released != nil {
		if !sameRequiredReceipt(*c.Required.Released, receipt) {
			return store.ErrCorrupt
		}
		return nil
	}
	if receipt.State == "active" {
		if !sameRequiredReceipt(c.Required.Reservation, receipt) {
			return store.ErrCorrupt
		}
		return nil
	}
	return checkRequiredUnreflectedRelease(c, receipt)
}

// checkRequiredInspectedIntent は元のbinding版を最初のintentへ正確に束縛し、集合の差替えを拒否する。
func checkRequiredInspectedIntent(row RequiredCaseInspection, r app.RequiredHoldReceipt) error {
	c, i := row.Current, row.Intent
	if i == nil || i.At < c.Created || r.At < i.At {
		return store.ErrCorrupt
	}
	if !requiredInspectedScopeMatches(c, *i, r) {
		return store.ErrCorrupt
	}
	if e := requiredItemsMatchReceipt(i.Items, r); e != nil {
		return e
	}
	return requiredItemsMatchReceipt(c.Items, r)
}

// requiredInspectedScopeMatches は最初の固定範囲/版/対象選択と現在署名期限へ元bindingを束縛する。
func requiredInspectedScopeMatches(c Case, i RequiredHoldIntent, r app.RequiredHoldReceipt) bool {
	return c.Revision >= i.Binding.Revision && requiredBindingMatchesScope(c, i.Binding) && r.Binding.Revision == i.Binding.Revision && requiredBindingMatchesScope(c, r.Binding) && r.Binding.Until <= c.RetentionUntil() && slices.Equal(c.Scope.Records, i.Records)
}

func sameRequiredReservationIdentity(a, b app.RequiredHoldReceipt) bool {
	return a.Binding == b.Binding && slices.Equal(a.Postings, b.Postings)
}

// checkRequiredUnreflectedReservation は初回元Sync後の案件参照未保存だけを許可する。
func checkRequiredUnreflectedReservation(c Case, r app.RequiredHoldReceipt) error {
	if r.State == "released" {
		if c.State != "releasing" && c.State != "closed" {
			return store.ErrCorrupt
		}
		return nil
	}
	if c.State == "releasing" || c.State == "closed" {
		return nil
	}
	if c.State != "preparing" && c.State != "partial" || r.Binding.Until != c.Until {
		return store.ErrIncomplete
	}
	return nil
}

// checkRequiredUnreflectedRelease は完成署名/取消後の元解除と案件解除参照の間だけを許可する。
func checkRequiredUnreflectedRelease(c Case, r app.RequiredHoldReceipt) error {
	if c.State != "active" && c.State != "releasing" && c.State != "closed" {
		return store.ErrCorrupt
	}
	h := *c.Required
	h.Released = &r
	return validateRequiredSourceRelease(&h, r.At)
}

// CheckRequiredCaseReservations は署名検査済み全案件/全元集合を双方向に照合する。
// 未反映の初回予約/終端解除だけを許し、孤立元・重複・案件参照の元欠落を拒否する。
func CheckRequiredCaseReservations(rows []RequiredCaseInspection, sources []app.RequiredHoldReceipt) error {
	if len(rows) > MaxCases || len(sources) > MaxCases {
		return ErrLimit
	}
	byCase, e := requiredInspectionByCase(rows)
	if e != nil {
		return e
	}
	seen := make(map[domain.ID]bool, len(sources))
	for _, receipt := range sources {
		id := receipt.Binding.Case
		row, found := byCase[id]
		if !found || seen[id] {
			return store.ErrCorrupt
		}
		if e = CheckRequiredCaseReservation(row, receipt); e != nil {
			return e
		}
		seen[id] = true
	}
	for _, row := range rows {
		if row.Current.Required != nil && !seen[row.Current.ID] {
			return store.ErrCorrupt
		}
	}
	return nil
}

// requiredInspectionByCase は署名検査済み案件のID重複を拒否し、元集合の双方向照合用に索引化する。
func requiredInspectionByCase(rows []RequiredCaseInspection) (map[domain.ID]RequiredCaseInspection, error) {
	result := make(map[domain.ID]RequiredCaseInspection, len(rows))
	for _, row := range rows {
		id := row.Current.ID
		if _, exists := result[id]; exists || id == (domain.ID{}) {
			return nil, store.ErrCorrupt
		}
		result[id] = row
	}
	return result, nil
}
