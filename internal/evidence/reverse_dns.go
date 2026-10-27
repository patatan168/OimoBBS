// 投稿時に観測したPTR回答を接続元へ結び、未確認の名前を確認済みとして扱わせない。
package evidence

import (
	"oimobbs/internal/domain"
	"slices"
	"strings"
)

// ReverseDNSObservation は接続元IPについて照会したDNSの固定結果。本人や所属の証明にはならない。
// confirmedのみConfirmedNameの正引きが接続元IPと一致する。Namesには未確認の有効なPTR名も含む。
type ReverseDNSObservation struct {
	Names         []string    `json:"names"`
	ConfirmedName string      `json:"confirmed_name"`
	Status        string      `json:"status"`
	ObservedAt    domain.Time `json:"observed_at_ns"`
	Resolver      string      `json:"resolver"`
}

// WithReverseDNS はDNS結果を独立コピーへ固定し、保存用の欠測一覧と業務検証を更新する。
func (v HTTPObservation) WithReverseDNS(value ReverseDNSObservation) (HTTPObservation, error) {
	value.Names = slices.Clone(value.Names)
	v.ReverseDNS = &value
	v.MissingFields = observationMissing(v)
	if err := ValidateHTTPObservationValue(v); err != nil {
		return HTTPObservation{}, err
	}
	return v, nil
}

func validReverseDNS(v *ReverseDNSObservation) bool {
	if v == nil {
		return true
	}
	if v.Names == nil || len(v.Names) > 16 || v.ObservedAt <= 0 || v.Resolver != "system" && v.Resolver != "google_https" {
		return false
	}
	if !slices.Contains([]string{"unchecked", "confirmed", "absent", "mismatch"}, v.Status) {
		return false
	}
	if v.Status == "confirmed" {
		if v.ConfirmedName == "" || !slices.Contains(v.Names, v.ConfirmedName) {
			return false
		}
	} else if v.ConfirmedName != "" {
		return false
	}
	if v.Status == "absent" && len(v.Names) != 0 {
		return false
	}
	previous := ""
	for _, name := range v.Names {
		if name <= previous || !validReverseHostname(name) {
			return false
		}
		previous = name
	}
	return true
}

func validReverseHostname(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
