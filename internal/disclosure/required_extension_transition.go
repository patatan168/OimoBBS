// 必須延長intentの期限先行確定・元参照差替え・取消後の復活を署名履歴から拒否する。
package disclosure

import (
	"oimobbs/internal/store"
	"slices"
)

// validateRequiredExtensionTransition はintentの先行署名、確認、取消後参照採用だけを許す。
func validateRequiredExtensionTransition(old, next Case, action string) error {
	if sameExtensionJSON(old.RequiredExtension, next.RequiredExtension) {
		if requiredExtensionPending(old) {
			return validateRequiredPendingTransition(old, next, action)
		}
		return nil
	}
	if action == "required_extend_intent" {
		return validateRequiredIntentTransition(old, next)
	}
	if action != "required_extend_complete" || !requiredExtensionPending(old) || next.RequiredExtension == nil {
		return store.ErrCorrupt
	}
	return validateRequiredCompleteTransition(old, next)
}

// validateRequiredPendingTransition は承認待ち中の旧期限/対象/元を維持し、署名取消/回収だけを許す。
func validateRequiredPendingTransition(old, next Case, action string) error {
	if old.Until != next.Until {
		return store.ErrCorrupt
	}
	switch action {
	case "release", "expire", "cleanup", "export_cleanup":
		return nil
	case "hold_reconciled", "hold_released":
		if next.State == "closed" || next.State == "releasing" {
			return nil
		}
	}
	if !sameRequiredFrozenCase(old, next) || !sameExtensionJSON(old.Required, next.Required) {
		return store.ErrCorrupt
	}
	return nil
}

// validateRequiredIntentTransition は元参照/固定集合を変えず、現在案件版の承認だけを作る。
func validateRequiredIntentTransition(old, next Case) error {
	x := next.RequiredExtension
	if requiredExtensionPending(old) || x == nil || x.State != "pending" || x.Revision != next.Revision || x.Previous != old.Until {
		return store.ErrCorrupt
	}
	return validateRequiredIntentOriginal(old, next)
}

// validateRequiredIntentOriginal は現予約と固定案件を先行承認の旧参照へ束縛する。
func validateRequiredIntentOriginal(old, next Case) error {
	if !sameRequiredFrozenCase(old, next) || next.Required == nil || next.Required.Released != nil {
		return store.ErrCorrupt
	}
	if old.State != "preparing" && old.State != "partial" {
		return store.ErrCorrupt
	}
	if !sameRequiredReceipt(next.Required.Reservation, next.RequiredExtension.Original) {
		return store.ErrCorrupt
	}
	if old.Required == nil {
		return nil
	}
	if old.Required.Released != nil || !sameExtensionJSON(old.Required, next.Required) {
		return store.ErrCorrupt
	}
	return nil
}

// validateRequiredCompleteTransition は同じintentの確認だけで元参照と期限を同時更新する。
func validateRequiredCompleteTransition(old, next Case) error {
	x := next.RequiredExtension
	if x.State != "complete" || x.Confirmed == nil || next.Required == nil || next.Until != x.Until || old.State != next.State {
		return store.ErrCorrupt
	}
	expected := *old.RequiredExtension
	expected.State = "complete"
	expected.Confirmed = x.Confirmed
	if !sameExtensionJSON(expected, *x) || !sameRequiredReceipt(next.Required.Reservation, *x.Confirmed) {
		return store.ErrCorrupt
	}
	if !sameRequiredExtensionContent(old, next) {
		return store.ErrCorrupt
	}
	return nil
}

// sameRequiredExtensionContent は期限/予約以外の対象集合と解除参照が変わっていないことを確認する。
func sameRequiredExtensionContent(old, next Case) bool {
	return sameRequiredScope(old.Scope, next.Scope) && slices.Equal(old.Items, next.Items) && sameExtensionJSON(old.Required.Released, next.Required.Released)
}

// requiredExtensionUpdatesReservation は確認署名/取消後採用の範囲内だけ元参照の更新を許す。
// actionの制限とintent全一致は先行のvalidateRequiredExtensionTransitionで検査する。
func requiredExtensionUpdatesReservation(old, next Case) bool {
	if !requiredExtensionPending(old) || old.Required == nil || next.Required == nil || old.Required.Released != nil {
		return false
	}
	if !sameExtensionJSON(old.Required.Released, next.Required.Released) {
		return false
	}
	if old.State == "closed" || old.State == "releasing" {
		return requiredExtensionReceiptMatches(*old.RequiredExtension, next.Required.Reservation, next.Required.Reservation.At)
	}
	return next.RequiredExtension != nil && next.RequiredExtension.State == "complete" && requiredExtensionReceiptMatches(*old.RequiredExtension, next.Required.Reservation, next.Required.Reservation.At)
}
