// 起動所有排他内で現在索引/完全候補と回収停止点を変更せず検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"time"
)

// InspectOptionalHoldIndexFiles は署名済み現在索引と完全候補を返す。補完やrenameを行わない。
func InspectOptionalHoldIndexFiles(root string, site domain.ID, key ed25519.PublicKey) (Event, *Event, error) {
	path := filepath.Join(root, optionalHoldsDir, optionalHoldIndexFile)
	raw, err := readOptionalPrivate(path, optionalHoldFileLimit)
	if err != nil {
		return Event{}, nil, err
	}
	current, err := decodeOptionalHoldIndexSigned(raw, site, key)
	if err != nil {
		return Event{}, nil, err
	}
	raw, err = readOptionalPrivate(path+".pending", optionalHoldFileLimit)
	if os.IsNotExist(err) {
		return current.event, nil, nil
	}
	if err != nil {
		return Event{}, nil, err
	}
	next, err := decodeOptionalHoldIndexSigned(raw, site, key)
	if err != nil {
		return Event{}, nil, err
	}
	if err := validateOptionalHoldIndexNext(current, next); err != nil {
		return Event{}, nil, err
	}
	return current.event, &next.event, nil
}

// InspectOptionalHoldRetirement は登録候補に対する全停止点/現存予約を読取りで照合する。
func InspectOptionalHoldRetirement(ctx context.Context, root string, site domain.ID, key ed25519.PrivateKey, candidate OptionalHoldRetirementCandidate, reader uint32, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if site == (domain.ID{}) || len(key) != ed25519.PrivateKeySize || reader < OptionalHoldRetirementReader {
		return store.ErrCorrupt
	}
	s := &OptionalStore{root: root, site: site, key: key}
	_, err := s.inspectOptionalRetirementResume(candidate, now)
	return err
}
