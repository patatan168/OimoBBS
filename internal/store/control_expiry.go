// 満了行の除去を記録の確定時刻とsystem操作へ束縛する。
package store

import (
	"encoding/json"
	"errors"

	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

// validateExpiredControlRemoval は起動再生でも壁時計を使わず、元満了と操作時刻を照合する。
// 行の完全型・除去できるcollectionは所有者のValueValidatorで別途検査する。
func validateExpiredControlRemoval(op ControlOperation, m Mutation, row ControlRow) error {
	if op.Actor.Kind != "system" || op.Actor.Reason != "expired_records_cleanup" || op.Result.Code != "expired_records_cleanup" || op.Result.RequestKey != nil || m.Expires != nil || len(row.Value) == 0 {
		return ErrCorrupt
	}
	var fields map[string]json.RawMessage
	if e := strictjson.Decode(row.Value, &fields); e != nil {
		return e
	}
	var expires domain.Time
	if e := json.Unmarshal(fields["expires_at_ns"], &expires); e != nil {
		return e
	}
	if expires <= 0 || expires > op.Committed {
		return errors.New("control record has not expired")
	}
	return nil
}
