// 元HTTP原本の回収復旧より前に、署名済み案件集合と元予約集合の対応を検査する。
package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"time"
)

// optionalHoldStartupCheck は案件正本を先に検査し、元原本の復旧を許可する読取り検査を返す。
// 起動時だけ案件の既知作成intentを再開し、案件期限回収はこの検査では行わない。
func optionalHoldStartupCheck(root string, key ed25519.PrivateKey, reader uint32, allowPending bool, state store.ControlState) (func(evidence.OptionalHoldReferences) error, error) {
	return optionalHoldStartupCheckAt(root, key, reader, allowPending, state, domain.Time(time.Now().UnixNano()))
}

// optionalHoldStartupCheckAt は試験も同じ署名時計境界へ明示的な現在時計を渡す。
func optionalHoldStartupCheckAt(root string, key ed25519.PrivateKey, reader uint32, allowPending bool, state store.ControlState, now domain.Time) (func(evidence.OptionalHoldReferences) error, error) {
	cases, e := optionalCaseStartupSnapshots(root, key, reader, allowPending)
	if e != nil {
		return nil, e
	}
	intents, e := verifiedRetirementIntents(state, key.Public().(ed25519.PublicKey), now)
	if e != nil {
		return nil, e
	}
	fingerprint := func(id domain.ID) domain.Hash {
		hash, _ := disclosure.CaseRetirementFingerprint(key, id)
		return hash
	}
	return optionalHoldRegisteredCheck(root, key, state, cases, intents, fingerprint, now)
}

// optionalCaseStartupSnapshots は通常案件の署名/readerを確認し、許可された作成途中だけを再開する。
func optionalCaseStartupSnapshots(root string, key ed25519.PrivateKey, reader uint32, allowPending bool) ([]disclosure.Case, error) {
	var cases []disclosure.Case
	var e error
	if allowPending {
		s, err := disclosure.Open(filepath.Join(root, "cases"), key)
		if err != nil {
			return nil, err
		}
		cases, e = s.Cases()
		e = joinCloseEvidenceCases(s, e)
	} else {
		cases, e = disclosure.InspectCaseMetadataVersion(filepath.Join(root, "cases"), key, reader)
	}
	if e != nil {
		return nil, e
	}
	for _, c := range cases {
		if !optionalCaseReaderValid(c, reader) {
			return nil, store.ErrCorrupt
		}
	}
	return cases, nil
}

// optionalCaseReaderValid はHTTP予約/解除/延長を読み取れる最低readerを確認する。
func optionalCaseReaderValid(c disclosure.Case, reader uint32) bool {
	if c.Extension != nil && reader < 44 {
		return false
	}
	if c.HTTP == nil {
		return true
	}
	if c.HTTP.Unbound && reader < 57 {
		return false
	}
	if reader < 41 || c.HTTP.Reservation != nil && reader < 42 {
		return false
	}
	return c.HTTP.Released == nil || reader >= 43
}

// joinCloseEvidenceCases は検査所有者を必ず閉じ、検査/Close両方の失敗を保持する。
func joinCloseEvidenceCases(s *disclosure.Store, prior error) error {
	return errors.Join(prior, s.Close())
}

// optionalHoldCasesCheck は信頼済み案件snapshotと全元予約をmetadataだけで照合する。
func optionalHoldCasesCheck(cases []disclosure.Case) func(evidence.OptionalHoldReferences) error {
	return func(source evidence.OptionalHoldReferences) error {
		rows, e := source.OptionalHoldReceipts()
		if e != nil {
			return e
		}
		byCase := make(map[domain.ID]disclosure.Case, len(cases))
		for _, c := range cases {
			byCase[c.ID] = c
		}
		seen := make(map[domain.ID]bool, len(rows))
		for _, receipt := range rows {
			c, exists := byCase[receipt.Binding.Case]
			if !exists {
				return store.ErrCorrupt
			}
			if e = checkOptionalHoldCase(c, receipt, source); e != nil {
				return e
			}
			seen[c.ID] = true
		}
		for _, c := range cases {
			if c.HTTP != nil && (c.HTTP.Reservation != nil || c.HTTP.Released != nil) && !seen[c.ID] {
				return store.ErrCorrupt
			}
		}
		return nil
	}
}

// checkOptionalHoldCase は固定範囲・集合を照合し、解除正本を署名済みコピー完了/取消と結ぶ。
func checkOptionalHoldCase(c disclosure.Case, receipt evidence.OptionalHoldReceipt, source evidence.OptionalHoldReferences) error {
	h := c.HTTP
	if !sameOptionalHoldCaseScope(c, receipt) || !sameOptionalHoldCaseItems(h.Items, receipt.Items) {
		return store.ErrCorrupt
	}
	if h.Released != nil {
		if e := source.CheckOptionalHoldRelease(*h.Released); e != nil {
			return e
		}
	}
	if h.Reservation != nil {
		if _, e := source.CheckOptionalHoldReceipt(*h.Reservation); e != nil {
			return e
		}
	} else if !initialOptionalHoldWithoutReference(c, receipt) {
		return store.ErrIncomplete
	}
	if e := checkOptionalHoldCaseState(c, receipt); e != nil {
		return e
	}
	return protectPendingOptionalExtension(c, source)
}

// sameOptionalHoldCaseScope は元所有者の予約が先行署名intentの範囲/版/期限に収まることを照合する。
func sameOptionalHoldCaseScope(c disclosure.Case, receipt evidence.OptionalHoldReceipt) bool {
	b := receipt.Binding
	h := c.HTTP
	if h == nil {
		return false
	}
	return b.Unbound == h.Unbound && b.Case == c.ID && receipt.Site == h.Site && receipt.At >= h.Captured && b.Board == c.Scope.Board && b.From == c.Scope.From && b.To == c.Scope.To && b.Revision <= c.Revision && b.Until <= c.RetentionUntil()
}

// sameOptionalHoldCaseItems は署名固定集合の元ID/hash/期限を順序も含めて照合する。
func sameOptionalHoldCaseItems(items []disclosure.Item, refs []evidence.OptionalHoldSource) bool {
	if len(items) != len(refs) {
		return false
	}
	for i, item := range items {
		ref := refs[i]
		if item.Record != ref.Record || item.Source != ref.SHA || item.Expires != ref.Expires {
			return false
		}
	}
	return true
}

// initialOptionalHoldWithoutReference は初回元Sync/取消解除後・案件参照未保存だけを許可する。
func initialOptionalHoldWithoutReference(c disclosure.Case, receipt evidence.OptionalHoldReceipt) bool {
	if receipt.State == "active" {
		return receipt.Sequence == 1
	}
	return receipt.State == "released" && receipt.Sequence == 2 && (c.State == "closed" || c.State == "releasing")
}

// checkOptionalHoldCaseState は未完了コピーの解除と、未反映の延長を回収許可へ混ぜない。
func checkOptionalHoldCaseState(c disclosure.Case, receipt evidence.OptionalHoldReceipt) error {
	terminal := c.State == "closed" || c.State == "releasing" || c.HTTP.State == "active"
	if receipt.State == "released" && !terminal {
		return store.ErrCorrupt
	}
	if receipt.State == "active" && !terminal && receipt.Binding.Until != c.Until && (c.Extension == nil || c.Extension.State != "pending" || receipt.Binding.Until != c.Extension.Until) {
		return store.ErrIncomplete
	}
	return nil
}

// protectPendingOptionalExtension は非終端の先行署名intentだけを元回収保護へ渡す。
func protectPendingOptionalExtension(c disclosure.Case, source evidence.OptionalHoldReferences) error {
	x := c.Extension
	if x == nil || x.State != "pending" || c.State == "closed" || c.State == "releasing" {
		return nil
	}
	b := x.Original.Binding
	b.Revision = x.Revision
	b.Until = x.Until
	return source.ProtectOptionalHoldRenewal(x.Original, b, x.Requested)
}
