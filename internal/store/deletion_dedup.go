// 本体回収後の再送拒否を、packと同じ固定長・CRC形式で引き継ぐ。
package store

import (
	"math"
	"time"

	"oimobbs/internal/domain"
)

// EncodeRejectedDedup は設計14のresult=2の160バイトentryを生成する。
// sourceSeqは回収元の確定位置。元の再送期限を変更せず、満了済みの入力は拒否する。
func EncodeRejectedDedup(d PackDedup, sourceSeq domain.U64, now domain.Time) ([]byte, error) {
	if e := validateRejectedDedup(d, sourceSeq, now); e != nil {
		return nil, e
	}
	return encodeDedupEntry(d, 2), nil
}

// DecodeRejectedDedup は再送拒否entryのCRC、予約領域、元期限と確定位置を検証する。
// acceptedのpack entryや満了済みのentryを再送成功として解釈しない。
func DecodeRejectedDedup(x []byte, sourceSeq domain.U64, now domain.Time) (PackDedup, error) {
	d, e := decodeDedupEntry(x, 2)
	if e != nil {
		return PackDedup{}, e
	}
	if e := validateRejectedDedup(d, sourceSeq, now); e != nil {
		return PackDedup{}, e
	}
	return d, nil
}

func validateRejectedDedup(d PackDedup, sourceSeq domain.U64, now domain.Time) error {
	v := d.Value
	duration := int64(30 * time.Second)
	if v.Mode == "explicit" && v.RequestID != nil {
		duration = int64(24 * time.Hour)
	} else if v.Mode != "implicit" || v.RequestID != nil {
		return ErrCorrupt
	}
	if d.ID == (domain.ID{}) || d.Seq == 0 || d.Seq > sourceSeq || d.Committed <= 0 || int64(d.Committed) > math.MaxInt64-duration || v.KeyID == 0 || v.PostNumber == 0 || v.Expires != d.Committed+domain.Time(duration) || v.Expires <= now {
		return ErrCorrupt
	}
	return nil
}
