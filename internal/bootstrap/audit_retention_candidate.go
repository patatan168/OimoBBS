// 監査保持期限の更新候補を保存先外へMAC付き保存し、現行正本と再照合する。
package bootstrap

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const retentionCandidateLimit = 8 << 20

type retentionOwner struct {
	Before      candidateOwner `json:"before_anchor"`
	BeforeProof auditTransfer  `json:"before_proof"`
	After       candidateOwner `json:"after_anchor"`
	AfterProof  auditTransfer  `json:"after_proof"`
}
type retentionCandidate struct {
	Schema  uint32           `json:"schema_version"`
	ID      domain.ID        `json:"id"`
	Site    domain.ID        `json:"site_id"`
	Created domain.Time      `json:"created_at_ns"`
	Owners  []retentionOwner `json:"owners"`
}

// AuditRetentionReport は保持下限候補の照合・適用結果。日別ファイルの削除許可を表さない。
type AuditRetentionReport struct {
	ID       domain.ID   `json:"candidate_id"`
	Owners   int         `json:"owner_count"`
	Since    domain.Time `json:"required_since_ns"`
	Verified bool        `json:"verified"`
	Applied  bool        `json:"applied"`
}

func retentionReport(m retentionCandidate) AuditRetentionReport {
	return AuditRetentionReport{ID: m.ID, Owners: len(m.Owners), Since: m.Created - domain.Time(auditRetention), Verified: true}
}

// PrepareAuditRetention は全所有者の再証明後だけ新規private候補を同期保存する。
// 初回snapshot切替が全所有者で完了している停止中の保存先を対象とする。
func (r *Repository) PrepareAuditRetention(ctx context.Context, output string) (AuditRetentionReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.candidatePath(output); err != nil {
		return AuditRetentionReport{}, err
	}
	m, err := r.buildRetentionCandidate(ctx, domain.NewID(), time.Now().UTC())
	if err != nil {
		return AuditRetentionReport{}, err
	}
	key, err := controlAnchorKey(r.cfg.DataDir)
	if err != nil {
		return AuditRetentionReport{}, err
	}
	defer clear(key[:])
	payload, err := json.Marshal(m)
	if err != nil {
		return AuditRetentionReport{}, err
	}
	// MACの用途文字列でsnapshot境界用のenvelopeと区別する。
	raw, err := json.Marshal(anchorEnvelope{payload, identity.MAC(key[:], "oimo/audit-retention-candidate/v1", payload)})
	if err != nil {
		return AuditRetentionReport{}, err
	}
	if len(raw) > retentionCandidateLimit {
		return AuditRetentionReport{}, store.ErrHistoryBudget
	}
	if err = ctx.Err(); err != nil {
		return AuditRetentionReport{}, err
	}
	if err = makePrivateDir(output); err != nil {
		return AuditRetentionReport{}, err
	}
	if err = writeNew(filepath.Join(output, "retention.json"), raw); err != nil {
		return AuditRetentionReport{}, err
	}
	if err = store.SyncDirectory(output); err != nil {
		return AuditRetentionReport{}, err
	}
	return retentionReport(m), nil
}

// VerifyAuditRetention は候補MACだけでなく、元境界・最新証明・日別正本・deltaを再照合する。
func (r *Repository) VerifyAuditRetention(ctx context.Context, input string) (AuditRetentionReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return AuditRetentionReport{}, err
	}
	m, err := readRetentionCandidate(r.cfg, input)
	if err != nil {
		return AuditRetentionReport{}, err
	}
	if m.Site != siteID(r.site.State()) {
		return AuditRetentionReport{}, store.ErrCorrupt
	}
	current, err := r.buildRetentionCandidate(ctx, m.ID, time.Unix(0, int64(m.Created)))
	if err != nil {
		return AuditRetentionReport{}, err
	}
	if !reflect.DeepEqual(m, current) {
		return AuditRetentionReport{}, errors.New("audit retention candidate is stale or differs")
	}
	return retentionReport(m), nil
}

// buildRetentionCandidate は現在状態を固定して、所有者順に旧証明と新証明を照合する。
func (r *Repository) buildRetentionCandidate(ctx context.Context, id domain.ID, at time.Time) (retentionCandidate, error) {
	if err := r.available(); err != nil {
		return retentionCandidate{}, err
	}
	if err := ctx.Err(); err != nil {
		return retentionCandidate{}, err
	}
	if len(r.anchors) != len(r.boards)+1 || len(r.anchors) > 129 {
		return retentionCandidate{}, errors.New("all owners must use authenticated snapshots")
	}
	m := retentionCandidate{Schema: 1, ID: id, Site: siteID(r.site.State()), Created: domain.Time(at.UnixNano()), Owners: []retentionOwner{}}
	ids := make([]domain.ID, 0, len(r.anchors))
	for owner := range r.anchors {
		ids = append(ids, owner)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	budget := store.HistoryBudget{Bytes: 128 << 20, Frames: 400000}
	archiveBudget := int64(64 << 20)
	for _, owner := range ids {
		before := r.anchors[owner]
		proof, entries, err := r.loadAuditProof(ctx, owner, before.Kind, &archiveBudget)
		if err != nil {
			return retentionCandidate{}, err
		}
		if proof == nil {
			return retentionCandidate{}, store.ErrCorrupt
		}
		err = r.withCandidateSource(ctx, AuditTransferOwner{Owner: owner, Kind: before.Kind, SourceSeq: proof.Sequence}, func(log *store.ControlLog) error {
			after, next, e := renewAuditBoundary(ctx, log, before, *proof, entries, at, &budget)
			if e != nil {
				return e
			}
			m.Owners = append(m.Owners, retentionOwner{before, *proof, after, next})
			return nil
		})
		if err != nil {
			return retentionCandidate{}, err
		}
	}
	return m, nil
}

// readRetentionCandidate は候補全体の完全型・MAC・時刻を検査する。現行状態との照合は呼出元で行う。
func readRetentionCandidate(cfg Config, input string) (retentionCandidate, error) {
	var m retentionCandidate
	r := Repository{cfg: cfg}
	if err := r.candidatePath(input); err != nil {
		return m, err
	}
	if err := requireEntries(input, []string{"retention.json"}); err != nil {
		return m, err
	}
	raw, err := readPrivate(filepath.Join(input, "retention.json"), retentionCandidateLimit)
	if err != nil {
		return m, err
	}
	var env anchorEnvelope
	if err = strictjson.Decode(raw, &env); err != nil {
		return m, err
	}
	key, err := controlAnchorKey(cfg.DataDir)
	if err != nil {
		return m, err
	}
	defer clear(key[:])
	want := identity.MAC(key[:], "oimo/audit-retention-candidate/v1", env.Payload)
	if !hmac.Equal(want[:], env.MAC[:]) {
		return m, store.ErrCorrupt
	}
	if err = strictjson.Decode(env.Payload, &m); err != nil {
		return m, err
	}
	if m.Schema != 1 || m.ID == (domain.ID{}) || m.Site == (domain.ID{}) || m.Created <= domain.Time(auditRetention) || m.Created > domain.Time(time.Now().UnixNano()) || len(m.Owners) == 0 || len(m.Owners) > 129 {
		return retentionCandidate{}, store.ErrCorrupt
	}
	return m, nil
}
