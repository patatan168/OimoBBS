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
	c, schema, e := decodeSelected(raw)
	if e != nil {
		return nil, e
	}
	if schema != Schema {
		return nil, nil
	}
	if e = validateKey(c, key); e != nil {
		return nil, e
	}
	return &c.Capture, nil
}

// ValidateKeyAndFrameMetadata は主体・要求HMACとframe対応を一度の完全復号で検証する。
// 他スキーマはnil,nil、いずれかの検証失敗はnil,errorを返し、metadataを共有しない。
func ValidateKeyAndFrameMetadata(raw, frame []byte, threadKey uint64, key domain.Hash) (*Capture, error) {
	c, schema, err := decodeSelected(raw)
	if err != nil {
		return nil, err
	}
	if schema != Schema {
		return nil, nil
	}
	if err = validateKey(c, key); err != nil {
		return nil, err
	}
	f, op, err := readFrame(frame)
	if err != nil {
		return nil, err
	}
	if err = validateFrame(c, f, op, frame, threadKey); err != nil {
		return nil, err
	}
	return &c.Capture, nil
}

// validateKey は完全検証済み成分から主体と要求のHMACを再計算する。
func validateKey(c decodedCapture, key domain.Hash) error {
	ip, e := netip.ParseAddr(c.Observation.Resolved.IP)
	if e != nil {
		return e
	}
	ip = ip.Unmap()
	family := byte(6)
	if ip.Is4() {
		family = 4
	}
	want := c.Input.Dedup(key, c.Observation.BoardID, uint64(c.Target), append([]byte{family}, ip.AsSlice()...), c.Committed)
	want.PostNumber = c.Dedup.PostNumber
	if !reflect.DeepEqual(want, c.Dedup) {
		return ErrCapture
	}
	return nil
}
