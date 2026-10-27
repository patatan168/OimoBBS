// carryの全件満了証跡を板正本へ固定し、元body証明・所有者・起動時計へ照合する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"time"
)

const bodyCarryRetirementReader = 58

type bodyCarryRetirementAnchor struct {
	Proof      app.BodyReclamation     `json:"body_reclamation"`
	Retirement app.BodyCarryRetirement `json:"carry_retirement"`
}

// decodeBodyCarryRetirementAnchor はcodecの完全型/固定key/署名表現を検査する。
// 暗号検証と最新元への照合は起動前と所有者列内で行う。
func decodeBodyCarryRetirementAnchor(key string, raw json.RawMessage) (bodyCarryRetirementAnchor, error) {
	var v bodyCarryRetirementAnchor
	if e := strictjson.Decode(raw, &v); e != nil {
		return v, e
	}
	if !bodyCarryAnchorScope(v, key) {
		return v, store.ErrCorrupt
	}
	if v.Retirement.ValidateFormat(v.Proof) != nil || v.Retirement.Proof != reclamationDigest(v.Proof) || !canonicalCarrySignature(v.Proof.Signature) {
		return v, store.ErrCorrupt
	}
	return v, nil
}

func bodyCarryAnchorScope(v bodyCarryRetirementAnchor, key string) bool {
	return v.Proof.Owner != (domain.ID{}) && v.Proof.Key != 0 && fmt.Sprint(v.Proof.Key) == key && v.Proof.Sequence > 0 && v.Proof.Sequence <= store.MaxPackEntries && v.Retirement.Dedups <= uint32(v.Proof.Sequence) && v.Retirement.Rates <= uint32(v.Proof.Sequence)
}

func canonicalCarrySignature(value string) bool {
	raw, e := base64.RawStdEncoding.Strict().DecodeString(value)
	return e == nil && len(raw) == ed25519.SignatureSize && base64.RawStdEncoding.EncodeToString(raw) == value
}

// validateBodyCarryRetirementAnchor は変更/削除/期限付けのない固定正本を検査する。
func validateBodyCarryRetirementAnchor(key string, old, next json.RawMessage) error {
	if len(old) != 0 {
		return store.ErrCorrupt
	}
	_, e := decodeBodyCarryRetirementAnchor(key, next)
	return e
}

// inspectBoardCarryRetirementRows は作成jobに属する板の期限なし参照を数える。
func inspectBoardCarryRetirementRows(state store.ControlState, owner domain.ID) (int, error) {
	count := 0
	for name, row := range state.Rows {
		key, found := strings.CutPrefix(name, "carry_retirement:")
		if !found {
			continue
		}
		v, e := decodeBodyCarryRetirementAnchor(key, row.Value)
		if e != nil {
			return 0, e
		}
		if v.Proof.Owner != owner || row.Expires != nil {
			return 0, store.ErrCorrupt
		}
		count++
	}
	return count, nil
}

// inspectBodyCarryRetirementAnchors はどの原本修復よりも先に独立正本と元bodyを照合する。
func inspectBodyCarryRetirementAnchors(cfg Config, site siteState, b persistedBoard, public ed25519.PublicKey) error {
	for name, row := range b.control.Rows {
		key, found := strings.CutPrefix(name, "carry_retirement:")
		if !found {
			continue
		}
		v, e := decodeBodyCarryRetirementAnchor(key, row.Value)
		if e != nil {
			return e
		}
		if site.MinimumReader < bodyCarryRetirementReader || v.Proof.Owner != b.info.ID || row.Expires != nil {
			return store.ErrCorrupt
		}
		if e = v.Retirement.Verify(v.Proof, domain.Time(time.Now().UnixNano()), public); e != nil {
			return e
		}
		if e = inspectCarryRetirementBody(cfg, v, public); e != nil {
			return e
		}
	}
	return nil
}

// inspectCarryRetirementBody は別のbody正本/元carryを、回収済みと誤認しない。
func inspectCarryRetirementBody(cfg Config, v bodyCarryRetirementAnchor, public ed25519.PublicKey) error {
	path := filepath.Join(cfg.DataDir, "expiry", v.Proof.Owner.String(), fmt.Sprint(v.Proof.Key))
	state, e := inspectDeletionControl(path, v.Proof.Owner, uint64(v.Proof.Key))
	if e != nil {
		return e
	}
	proof, e := readBodyReclamation(state, v.Proof.Owner, uint64(v.Proof.Key), public)
	if e != nil || proof == nil || reclamationDigest(*proof) != v.Retirement.Proof {
		return store.ErrCorrupt
	}
	task, e := bodyTask(state, proof.Deletion)
	if e != nil || task.State != "complete" {
		return store.ErrCorrupt
	}
	seal, e := readBodyCarry(state, *proof)
	if e != nil || seal == nil {
		return store.ErrCorrupt
	}
	return verifyBoundCarryRetirement(v.Retirement, *proof, *seal, domain.Time(time.Now().UnixNano()), public)
}
