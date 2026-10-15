// 認証済み保持下限より完全に古い監査日を列挙し、回収計画をMACで保存する。
package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const auditReclaimIntent = ".audit-reclaim"
const auditReclaimLimit = 4 << 20

type auditReclaimOwner struct {
	Anchor candidateOwner `json:"anchor"`
	Proof  auditTransfer  `json:"proof"`
}
type auditReclaimFile struct {
	Name string      `json:"name"`
	Size domain.U64  `json:"size"`
	SHA  domain.Hash `json:"sha256"`
}
type auditReclaimDay struct {
	Owner domain.ID          `json:"owner"`
	Kind  string             `json:"kind"`
	Day   string             `json:"day"`
	Files []auditReclaimFile `json:"files"`
}
type auditReclaimPlan struct {
	Schema uint32              `json:"schema_version"`
	Site   domain.ID           `json:"site"`
	Owners []auditReclaimOwner `json:"owners"`
	Days   []auditReclaimDay   `json:"days"`
}

// AuditReclaimReport のBytesは今回列挙したfileの論理byte数。全コピーの消去や物理解放量ではない。
type AuditReclaimReport struct {
	Owners   int        `json:"owners"`
	Days     int        `json:"days"`
	Bytes    domain.U64 `json:"bytes"`
	Verified bool       `json:"verified"`
	Applied  bool       `json:"applied"`
}

func auditReclaimReport(p auditReclaimPlan) AuditReclaimReport {
	out := AuditReclaimReport{Owners: len(p.Owners), Days: len(p.Days), Verified: true}
	for _, day := range p.Days {
		for _, file := range day.Files {
			out.Bytes += file.Size
		}
	}
	return out
}

// buildAuditReclaimPlan は最新証明の日と保持下限を跨ぐ日を残し、全対象を有界に検査する。
func (r *Repository) buildAuditReclaimPlan(ctx context.Context) (auditReclaimPlan, error) {
	proof, err := r.VerifyAuditTransfer(ctx)
	if err != nil {
		return auditReclaimPlan{}, err
	}
	if !proof.Complete {
		return auditReclaimPlan{}, errors.New("audit transfer must be complete before reclaim")
	}
	p := auditReclaimPlan{Schema: 1, Site: siteID(r.site.State()), Owners: []auditReclaimOwner{}, Days: []auditReclaimDay{}}
	ids := make([]domain.ID, 0, len(r.anchors))
	for id := range r.anchors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	archiveBudget := int64(64 << 20)
	fileBudget := int64(64 << 20)
	for _, id := range ids {
		a := r.anchors[id]
		latest, _, err := r.loadAuditProof(ctx, id, a.Kind, &archiveBudget)
		if err != nil {
			return p, err
		}
		if latest == nil || latest.Since != a.Proof.Since {
			return p, store.ErrCorrupt
		}
		p.Owners = append(p.Owners, auditReclaimOwner{a, *latest})
		root := filepath.Join(r.cfg.DataDir, "audit", id.String())
		names, err := boundedAuditNames(root, 4096)
		if err != nil {
			return p, err
		}
		sort.Strings(names)
		for _, name := range names {
			if err = ctx.Err(); err != nil {
				return p, err
			}
			at, err := time.Parse("20060102", name)
			if err != nil {
				return p, err
			}
			if at.AddDate(0, 0, 1).UnixNano() > int64(a.Proof.Since) || name == time.Unix(0, int64(latest.Imported)).UTC().Format("20060102") {
				continue
			}
			if len(p.Days) >= 1024 {
				return p, store.ErrHistoryBudget
			}
			day := auditReclaimDay{Owner: id, Kind: a.Kind, Day: name, Files: []auditReclaimFile{}}
			path := filepath.Join(root, name)
			if err = requireEntries(path, []string{"control.current", "control-000001.wal"}); err != nil {
				return p, err
			}
			for _, file := range []string{"control.current", "control-000001.wal"} {
				raw, err := readPrivate(filepath.Join(path, file), fileBudget)
				if err != nil {
					return p, err
				}
				fileBudget -= int64(len(raw))
				day.Files = append(day.Files, auditReclaimFile{file, domain.U64(len(raw)), sha256.Sum256(raw)})
			}
			p.Days = append(p.Days, day)
		}
	}
	return p, nil
}

func encodeAuditReclaim(cfg Config, p auditReclaimPlan) ([]byte, error) {
	key, err := controlAnchorKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(anchorEnvelope{payload, identity.MAC(key[:], "oimo/audit-reclaim/v1", payload)})
	if len(raw) > auditReclaimLimit {
		return nil, store.ErrHistoryBudget
	}
	return raw, err
}

func decodeAuditReclaim(cfg Config, raw []byte) (auditReclaimPlan, error) {
	var p auditReclaimPlan
	var env anchorEnvelope
	if err := strictjson.Decode(raw, &env); err != nil {
		return p, err
	}
	key, err := controlAnchorKey(cfg.DataDir)
	if err != nil {
		return p, err
	}
	defer clear(key[:])
	want := identity.MAC(key[:], "oimo/audit-reclaim/v1", env.Payload)
	if !hmac.Equal(want[:], env.MAC[:]) {
		return p, store.ErrCorrupt
	}
	if err = strictjson.Decode(env.Payload, &p); err != nil {
		return p, err
	}
	if p.Schema != 1 || p.Site == (domain.ID{}) || len(p.Owners) > 129 || len(p.Days) > 1024 {
		return p, store.ErrCorrupt
	}
	return p, nil
}

// boundedAuditNames は作業領域や日別一覧の過大な列挙を拒否する。
func boundedAuditNames(path string, limit int) ([]string, error) {
	if err := privatePath(path, true); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(limit + 1)
	if err == io.EOF {
		err = nil
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, err
	}
	if len(names) > limit {
		return nil, store.ErrHistoryBudget
	}
	return names, nil
}
