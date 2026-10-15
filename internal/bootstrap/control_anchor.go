// 検証済みsnapshot境界を用途分離したMACで認証し、0600で永続化する。
package bootstrap

import (
	"crypto/hmac"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const anchorLimit = 16 << 10

type controlAnchor struct {
	Schema    uint32         `json:"schema_version"`
	Site      domain.ID      `json:"site_id"`
	Candidate domain.ID      `json:"candidate_id"`
	Owner     candidateOwner `json:"owner"`
}
type anchorEnvelope struct {
	Payload json.RawMessage `json:"payload"`
	MAC     domain.Hash     `json:"mac"`
}

// controlAnchorKey はmasterから境界専用鍵を導出する。鍵は返却先でclearする。
func controlAnchorKey(root string) (domain.Hash, error) {
	master, err := readPrivate(filepath.Join(root, "keys", "master-000001.key"), 32)
	if err != nil {
		return domain.Hash{}, err
	}
	defer clear(master)
	return identity.DeriveKey(master, "control_anchor", 1)
}

func anchorFile(item candidateOwner) string {
	return item.Kind + "-" + item.Owner.String() + ".anchor.json"
}

// validateAnchor は認証後にも所有境界・世代・監査証明の完全型を確認する。
func validateAnchor(a controlAnchor) error {
	o := a.Owner
	if a.Schema != 1 || a.Site == (domain.ID{}) || a.Candidate == (domain.ID{}) || o.Owner == (domain.ID{}) || (o.Kind != "site" && o.Kind != "board") || (o.Kind == "site" && o.Owner != a.Site) || (o.Kind == "board" && o.Owner == a.Site) || o.Generation < 2 || o.Sequence == 0 || o.Rows == 0 || o.Rows > 200000 || o.Length < 64 || o.Length > candidateLimit || o.SHA == (domain.Hash{}) || o.File != o.Kind+"-"+o.Owner.String()+".snap" || o.Proof.Sequence != o.Sequence || o.Proof.Generation >= o.Generation {
		return store.ErrCorrupt
	}
	raw, err := json.Marshal(o.Proof)
	if err != nil {
		return err
	}
	day := time.Unix(0, int64(o.Proof.Imported)).UTC().Format("20060102")
	return validateAuditTransfer(o.Owner, o.Kind, day, nil, raw)
}

// writeControlAnchor は照合直後の境界だけを呼出元から受け取り、既存fileを上書きしない。
func writeControlAnchor(path string, a controlAnchor, key domain.Hash) error {
	if key == (domain.Hash{}) {
		return store.ErrCorrupt
	}
	if err := validateAnchor(a); err != nil {
		return err
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(anchorEnvelope{payload, identity.MAC(key[:], "oimo/control-anchor/v1", payload)})
	if err != nil {
		return err
	}
	if len(raw) > anchorLimit {
		return store.ErrHistoryBudget
	}
	if err = writeNew(path, raw); err != nil {
		return err
	}
	return store.SyncDirectory(filepath.Dir(path))
}

// readControlAnchor はMAC・site・candidateを照合する。candidateがゼロならsite束縛だけを要求する。
func readControlAnchor(path string, site, candidate domain.ID, key domain.Hash) (controlAnchor, error) {
	var a controlAnchor
	if key == (domain.Hash{}) || site == (domain.ID{}) {
		return a, store.ErrCorrupt
	}
	raw, err := readPrivate(path, anchorLimit)
	if err != nil {
		return a, err
	}
	var env anchorEnvelope
	if err = strictjson.Decode(raw, &env); err != nil {
		return a, err
	}
	want := identity.MAC(key[:], "oimo/control-anchor/v1", env.Payload)
	if !hmac.Equal(want[:], env.MAC[:]) {
		return a, store.ErrCorrupt
	}
	if err = strictjson.Decode(env.Payload, &a); err != nil {
		return controlAnchor{}, err
	}
	if err = validateAnchor(a); err != nil {
		return controlAnchor{}, err
	}
	if a.Site != site || (candidate != (domain.ID{}) && a.Candidate != candidate) {
		return controlAnchor{}, store.ErrCorrupt
	}
	return a, nil
}

func verifyCandidateAnchor(dir string, m controlCandidate, item candidateOwner, key domain.Hash) error {
	a, err := readControlAnchor(filepath.Join(dir, anchorFile(item)), m.Site, m.ID, key)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a.Owner, item) {
		return store.ErrCorrupt
	}
	return nil
}
