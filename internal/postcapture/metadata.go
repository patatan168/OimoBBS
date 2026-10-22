// 投稿主体のHMACと完全型を一度に検査し、その呼出し専用のmetadataを返す。
package postcapture

import (
	"net/netip"
	"oimobbs/internal/domain"
	"reflect"
)

// ValidateKeyAndMetadata は現行form成分を完全型検証し、主体と要求のHMACを再計算する。
// 成功時のCaptureは呼出し専用で変更可能。別スキーマはnil,nilを返し、その検証は呼出元に委ねる。
// 不正な型・IP・HMACではmetadataを返さない。検証結果を別呼出しへ保持しない。
func ValidateKeyAndMetadata(raw []byte, key domain.Hash) (*Capture, error) {
	schema, e := schemaOf(raw)
	if e != nil {
		return nil, e
	}
	if schema != Schema {
		return nil, nil
	}
	c, e := decode(raw)
	if e != nil {
		return nil, e
	}
	ip, e := netip.ParseAddr(c.Observation.Resolved.IP)
	if e != nil {
		return nil, e
	}
	ip = ip.Unmap()
	family := byte(6)
	if ip.Is4() {
		family = 4
	}
	want := c.Input.Dedup(key, c.Observation.BoardID, uint64(c.Target), append([]byte{family}, ip.AsSlice()...), c.Committed)
	want.PostNumber = c.Dedup.PostNumber
	if !reflect.DeepEqual(want, c.Dedup) {
		return nil, ErrCapture
	}
	return &c.Capture, nil
}
