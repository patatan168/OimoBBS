// 受理操作なしのHTTP元予約を明示し、既存の受理操作予約と署名bytesを維持する。
package evidence

import (
	"context"
	"slices"
	"time"
)

// validOptionalHoldOperations は予約種別と受理操作集合の混在を拒否する。
func validOptionalHoldOperations(b OptionalHoldBinding) bool {
	if b.Unbound {
		return b.Operations != nil && len(b.Operations) == 0
	}
	return len(b.Operations) > 0 && len(b.Operations) <= MaxOptionalQueryRecords
}

// optionalHoldRecordMatches は全種別で実板/期間を照合し、受理操作あり/なしを混ぜない。
func optionalHoldRecordMatches(b OptionalHoldBinding, r OptionalRecord) bool {
	if r.Board == nil || *r.Board != b.Board || r.Received < b.From || r.Received >= b.To {
		return false
	}
	if b.Unbound {
		return r.Operation == nil && r.Outcome != "accepted" && r.Outcome != "duplicate"
	}
	return r.Operation != nil && slices.Contains(b.Operations, *r.Operation)
}

// QueryUnboundSigned は保全intent用の受理操作なし原本を同じ期限/件数/署名検査で取得する。
// 原本の取得だけで保全予約を作らない。呼出元は先行intent後に既存ReserveOptionalHoldへ渡す。
func (s *OptionalStore) QueryUnboundSigned(ctx context.Context, scope OptionalQueryScope, now time.Time) ([]Entry, error) {
	return s.queryEntries(ctx, scope, now, true)
}
