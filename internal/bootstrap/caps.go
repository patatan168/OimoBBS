// サイト所有のキャップを完全型で保持し、認証済み資格を投稿時刻と担当板へ束縛する。
package bootstrap

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
)

var ErrCap = errors.New("invalid or unavailable posting cap")

type capValue struct {
	ID          domain.ID    `json:"id"`
	Name        string       `json:"display_name"`
	Secret      domain.Hash  `json:"secret_hash"`
	KeyID       uint32       `json:"key_id"`
	Boards      []domain.ID  `json:"board_ids"`
	Permissions []string     `json:"permissions"`
	Enabled     bool         `json:"enabled"`
	Expires     domain.Time  `json:"expires_at_ns"`
	Revision    domain.U64   `json:"revision"`
	Created     domain.Time  `json:"created_at_ns"`
	Revoked     *domain.Time `json:"revoked_at_ns"`
}

// AdminCap は秘密/hashを含まない管理表示。原資格の有効期限を延ばさない。
type AdminCap struct {
	ID          domain.ID   `json:"id"`
	Name        string      `json:"display_name"`
	Boards      []domain.ID `json:"board_ids"`
	Permissions []string    `json:"permissions"`
	Enabled     bool        `json:"enabled"`
	Expires     domain.Time `json:"expires_at_ns"`
	Revision    domain.U64  `json:"revision"`
}

// ExpiryLabel は期限を時刻として表示する。保存値のns表記を画面へ露出させない。
func (v AdminCap) ExpiryLabel() string {
	if v.Expires == 0 {
		return "期限なし"
	}
	return time.Unix(0, int64(v.Expires)).In(domain.JST).Format(time.RFC3339)
}

// StatusLabel は削除と期限切れを区別し、現在投稿に使える資格だけを有効と表示する。
func (v AdminCap) StatusLabel() string {
	return capStatusAt(v, domain.Time(time.Now().UnixNano()))
}

func capStatusAt(v AdminCap, now domain.Time) string {
	if !v.Enabled {
		return "削除済み"
	}
	if v.Expires != 0 && v.Expires <= now {
		return "期限切れ"
	}
	return "有効"
}

// ETag は対象資格の保存版へ束縛する。
func (v AdminCap) ETag() string { return fmt.Sprintf(`"cap:%s:%d"`, v.ID, v.Revision) }
func capView(v capValue) AdminCap {
	return AdminCap{v.ID, v.Name, slices.Clone(v.Boards), slices.Clone(v.Permissions), v.Enabled, v.Expires, v.Revision}
}

type capRegistry struct{ Records map[domain.ID]capValue }

func validCapName(name string) bool {
	normalized, e := compat.Normalize(name, false, false)
	return validName(name) && e == nil && normalized == name && !strings.ContainsAny(name, "◆★●")
}
func validateCapState(v capValue) error {
	if v.ID == (domain.ID{}) || !validCapName(v.Name) || v.Secret == (domain.Hash{}) || v.KeyID != 9 || v.Created <= 0 || v.Expires != 0 && v.Expires <= v.Created || len(v.Boards) < 1 || len(v.Boards) > 128 || len(v.Permissions) < 1 || len(v.Permissions) > 2 {
		return store.ErrCorrupt
	}
	prior := ""
	for _, id := range v.Boards {
		if id == (domain.ID{}) || id.String() <= prior {
			return store.ErrCorrupt
		}
		prior = id.String()
	}
	prior = ""
	for _, p := range v.Permissions {
		if p != "post" && p != "create" || p <= prior {
			return store.ErrCorrupt
		}
		prior = p
	}
	if v.Enabled {
		if v.Revision != 1 || v.Revoked != nil {
			return store.ErrCorrupt
		}
	} else if v.Revision != 2 || v.Revoked == nil || *v.Revoked < v.Created {
		return store.ErrCorrupt
	}
	return nil
}
func validateCapValue(key string, old, next json.RawMessage) error {
	var v capValue
	if strictjson.Decode(next, &v) != nil || key != v.ID.String() || validateCapState(v) != nil {
		return store.ErrCorrupt
	}
	if len(old) == 0 {
		if !v.Enabled {
			return store.ErrCorrupt
		}
		return nil
	}
	var p capValue
	if strictjson.Decode(old, &p) != nil || !p.Enabled || v.Enabled {
		return store.ErrCorrupt
	}
	p.Enabled, p.Revision, p.Revoked = v.Enabled, v.Revision, v.Revoked
	if !reflect.DeepEqual(p, v) {
		return store.ErrCorrupt
	}
	return nil
}
func capSecret(key domain.Hash, id domain.ID, secret string) domain.Hash {
	return identity.MAC(key[:], "oimo/cap-secret/v1", id[:], []byte(secret))
}
func (v capValue) permits(board domain.ID, create bool, at domain.Time) bool {
	permission := "post"
	if create {
		permission = "create"
	}
	return v.Enabled && at >= v.Created && (v.Expires == 0 || at < v.Expires) && slices.Contains(v.Boards, board) && slices.Contains(v.Permissions, permission)
}

// authenticateCap は用途鍵9で定数時間照合し、原秘密を状態・公開DTO・監査へ保存しない。
func authenticateCap(reg *capRegistry, key domain.Hash, id domain.ID, secret string, board domain.ID, create bool, at domain.Time) (*capValue, error) {
	actual := capSecret(key, id, secret)
	var expected domain.Hash
	var v capValue
	if reg != nil {
		v = reg.Records[id]
		expected = v.Secret
	}
	if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 || !v.permits(board, create, at) {
		return nil, ErrCap
	}
	return &v, nil
}
func loadCapRegistry(state store.ControlState) (*capRegistry, error) {
	reg := &capRegistry{Records: map[domain.ID]capValue{}}
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "cap:") {
			continue
		}
		var v capValue
		if strictjson.Decode(row.Value, &v) != nil || name != "cap:"+v.ID.String() || validateCapState(v) != nil {
			return nil, store.ErrCorrupt
		}
		reg.Records[v.ID] = v
	}
	if len(reg.Records) > 10000 {
		return nil, store.ErrCorrupt
	}
	return reg, nil
}

// validateCapCapture は旧受理も失効前の時刻で照合し、停止済み資格を復活させない。
func validateCapCapture(raw []byte, reg *capRegistry, board domain.ID) error {
	proof, at, create, e := postcapture.CapMetadata(raw)
	if e != nil || proof == nil {
		return e
	}
	return validateCapEvidence(proof, at, create, reg, board)
}

// validateCapEvidence は型検証済みの資格を、有効期間・板・投稿権限へ照合する。
func validateCapEvidence(proof *postcapture.CapEvidence, at domain.Time, create bool, reg *capRegistry, board domain.ID) error {
	if proof == nil {
		return nil
	}
	if reg == nil {
		return ErrCap
	}
	v, ok := reg.Records[proof.ID]
	if !ok || proof.Revision != 1 || proof.Name != v.Name || proof.KeyID != v.KeyID || at < v.Created || v.Expires != 0 && at >= v.Expires || v.Revoked != nil && at >= *v.Revoked || !slices.Contains(v.Boards, board) {
		return ErrCap
	}
	permission := "post"
	if create {
		permission = "create"
	}
	if !slices.Contains(v.Permissions, permission) {
		return ErrCap
	}
	return nil
}

// readCapKey は保存先のmasterから用途鍵9だけを導出し、読取ったmasterを消去する。
func readCapKey(r *Repository) (domain.Hash, error) {
	master, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if e != nil {
		return domain.Hash{}, e
	}
	defer clear(master)
	return identity.DeriveKey(master, "cap", 9)
}
