// 現在サイトの回収登録がある場合だけ、reader61の照合付き元所有者を選択する。
package bootstrap

import (
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"strings"
	"time"
)

func optionalHoldRetirementEnabled(state store.ControlState) bool {
	for name := range state.Rows {
		if strings.HasPrefix(name, optionalHoldRetirementCollection+":") {
			return true
		}
	}
	return false
}

// openOptionalSourceChecked は原本復旧より先に現在登録と元索引/参照を照合する。
func openOptionalSourceChecked(root string, site siteState, key ed25519.PrivateKey, state store.ControlState, check func(evidence.OptionalHoldReferences) error) (*evidence.OptionalStore, error) {
	if optionalHoldRetirementEnabled(state) {
		return evidence.OpenOptionalStoreRetirementChecked(root, site.ID, key, site.MinimumReader, check)
	}
	return evidence.OpenOptionalStoreChecked(root, site.ID, key, check)
}

// inspectOptionalSourceChecked は回収対応索引も時計床付きで読取り検査する。fileを補完しない。
func inspectOptionalSourceChecked(root string, site siteState, key ed25519.PrivateKey, state store.ControlState, now time.Time, check func(evidence.OptionalHoldReferences) error) error {
	if optionalHoldRetirementEnabled(state) {
		return evidence.InspectOptionalStoreRetirementChecked(root, site.ID, key, site.MinimumReader, domain.Time(now.UnixNano()), check)
	}
	return evidence.InspectOptionalStoreChecked(root, site.ID, key, check)
}
