// 制御snapshotの候補を稼働領域の外へ保存する。正本の切替・履歴削除は行わない。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const candidateLimit = 64 << 20

// ControlSnapshotReport は値や資格情報を含まない候補の検査結果。Verifiedは切替許可ではない。
type ControlSnapshotReport struct {
	ID        domain.ID  `json:"candidate_id"`
	Owners    int        `json:"owner_count"`
	Bytes     domain.U64 `json:"snapshot_bytes"`
	Verified  bool       `json:"verified"`
	Activated bool       `json:"activated"`
}

type controlCandidate struct {
	Schema  uint32           `json:"schema_version"`
	ID      domain.ID        `json:"id"`
	Site    domain.ID        `json:"site_id"`
	Created domain.Time      `json:"created_at_ns"`
	Level   int              `json:"compression_level"`
	Owners  []candidateOwner `json:"owners"`
}
type candidateOwner struct {
	Owner      domain.ID     `json:"owner_id"`
	Kind       string        `json:"owner_kind"`
	Generation domain.U64    `json:"generation"`
	Sequence   domain.U64    `json:"seq"`
	Rows       uint32        `json:"row_count"`
	File       string        `json:"file"`
	Length     domain.U64    `json:"length"`
	SHA        domain.Hash   `json:"sha256"`
	Proof      auditTransfer `json:"audit_transfer"`
}

// candidatePath はデータ領域外・非symlink・所有者限定の出力親を要求する。
func (r *Repository) candidatePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("candidate path must be absolute and clean")
	}
	rel, e := filepath.Rel(r.cfg.DataDir, path)
	if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("candidate must be outside the data directory")
	}
	return privatePath(filepath.Dir(path), true)
}

func (o candidateOwner) header() store.Header {
	kind := uint16(1)
	if o.Kind == "board" {
		kind = 2
	}
	return store.Header{Kind: kind, Owner: o.Owner, Generation: uint64(o.Generation), BaseSeq: uint64(o.Sequence)}
}

// withCandidateSource は板状態をワーカー内で読み、移管検査時のseqとの一致を確認する。
func (r *Repository) withCandidateSource(ctx context.Context, owner AuditTransferOwner, fn func(*store.ControlLog) error) error {
	read := func(log *store.ControlLog) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if log == nil || log.State().Seq != owner.SourceSeq {
			return errors.New("source changed after audit verification")
		}
		return fn(log)
	}
	if owner.Kind == "site" {
		return read(r.site)
	}
	if b := r.posting[owner.Owner]; b != nil {
		_, e := b.worker.Submit(ctx, func() (any, error) {
			if b.stopped {
				return nil, ErrPostingUnavailable
			}
			return nil, read(b.control)
		})
		return e
	}
	return read(r.boards[owner.Owner])
}

// requireCandidateProof は全site/boardの最新seqまで監査移管が検証できた場合だけ進む。
func (r *Repository) requireCandidateProof(ctx context.Context) (AuditTransferReport, error) {
	report, e := r.verifyAuditTransferLocked(ctx)
	if e != nil {
		return report, e
	}
	if !report.Complete {
		return report, errors.New("audit transfer is incomplete; refresh the audit list before preparing a snapshot")
	}
	return report, nil
}

// PrepareControlSnapshot は同期済み候補を新規ディレクトリへ書く。途中失敗のディレクトリは残し、再利用しない。
// 最後にcandidate.jsonを同期保存し、稼働current・WALや最低reader版は変更しない。
func (r *Repository) PrepareControlSnapshot(ctx context.Context, output string, level int) (ControlSnapshotReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return ControlSnapshotReport{}, e
	}
	if level != 0 && level != 1 && level != 6 && level != 9 {
		return ControlSnapshotReport{}, errors.New("snapshot level must be 0, 1, 6, or 9")
	}
	if e := r.candidatePath(output); e != nil {
		return ControlSnapshotReport{}, e
	}
	proof, e := r.requireCandidateProof(ctx)
	if e != nil {
		return ControlSnapshotReport{}, e
	}
	if e = makePrivateDir(output); e != nil {
		return ControlSnapshotReport{}, e
	}
	key, e := controlAnchorKey(r.cfg.DataDir)
	if e != nil {
		return ControlSnapshotReport{}, e
	}
	defer clear(key[:])
	manifest := controlCandidate{Schema: 2, ID: domain.NewID(), Site: siteID(r.site.State()), Created: domain.Time(time.Now().UnixNano()), Level: level, Owners: []candidateOwner{}}
	result := ControlSnapshotReport{ID: manifest.ID}
	archiveBudget := int64(candidateLimit)
	for _, owner := range proof.Owners {
		e = r.withCandidateSource(ctx, owner, func(log *store.ControlLog) error {
			if err := r.inspectSnapshotState(owner, log.State()); err != nil {
				return err
			}
			source := log.HistoryHeader()
			state := log.State()
			if source.BaseSeq != 0 || source.Generation == math.MaxUint64 {
				return errors.New("unsupported source generation")
			}
			transfer, _, err := r.loadAuditProof(ctx, owner.Owner, owner.Kind, &archiveBudget)
			if err != nil {
				return err
			}
			if transfer == nil || transfer.Sequence != state.Seq {
				return store.ErrCorrupt
			}
			item := candidateOwner{Owner: owner.Owner, Kind: owner.Kind, Generation: domain.U64(source.Generation + 1), Sequence: state.Seq, Rows: uint32(len(state.Rows)), File: owner.Kind + "-" + owner.Owner.String() + ".snap", Proof: *transfer}
			raw, err := store.EncodeControlSnapshot(item.header(), state, level, snapshotValues(item.Kind))
			if err != nil {
				return err
			}
			item.Length = domain.U64(len(raw))
			item.SHA = sha256.Sum256(raw)
			if result.Bytes+item.Length > candidateLimit {
				return store.ErrHistoryBudget
			}
			if err = writeNew(filepath.Join(output, item.File), raw); err != nil {
				return err
			}
			if err = verifyCandidateFile(output, item, state, level); err != nil {
				return err
			}
			if err = writeControlAnchor(filepath.Join(output, anchorFile(item)), controlAnchor{1, manifest.Site, manifest.ID, item}, key); err != nil {
				return err
			}
			manifest.Owners = append(manifest.Owners, item)
			result.Owners++
			result.Bytes += item.Length
			return nil
		})
		if e != nil {
			return ControlSnapshotReport{}, e
		}
		r.checkpoint("snapshot_candidate_file")
	}
	if e = ctx.Err(); e != nil {
		return ControlSnapshotReport{}, e
	}
	raw, e := json.Marshal(manifest)
	if e != nil {
		return ControlSnapshotReport{}, e
	}
	if len(raw) > 1<<20 {
		return ControlSnapshotReport{}, store.ErrHistoryBudget
	}
	if e = writeNew(filepath.Join(output, "candidate.json"), raw); e != nil {
		return ControlSnapshotReport{}, e
	}
	if e = store.SyncDirectory(output); e != nil {
		return ControlSnapshotReport{}, e
	}
	result.Verified = true
	return result, nil
}

// readCandidateManifest は秘密を含む可能性のある候補を有界・厳密に読み込む。
func readCandidateManifest(dir string) (controlCandidate, error) {
	var m controlCandidate
	if e := privatePath(dir, true); e != nil {
		return m, e
	}
	raw, e := readPrivate(filepath.Join(dir, "candidate.json"), 1<<20)
	if e != nil {
		return m, e
	}
	if e = strictjson.Decode(raw, &m); e != nil {
		return m, e
	}
	if m.Schema != 2 || m.ID == (domain.ID{}) || m.Site == (domain.ID{}) || m.Created <= 0 || m.Created > domain.Time(time.Now().UnixNano()) || len(m.Owners) == 0 || len(m.Owners) > 129 || (m.Level != 0 && m.Level != 1 && m.Level != 6 && m.Level != 9) {
		return m, store.ErrCorrupt
	}
	return m, nil
}

// verifyCandidateFile はSHA・codecと元状態の全行を照合し、revision・expiresの変化も拒否する。
func verifyCandidateFile(dir string, item candidateOwner, state store.ControlState, level int) error {
	if item.File != item.Kind+"-"+item.Owner.String()+".snap" || item.Length < 64 || item.Length > candidateLimit || item.Rows != uint32(len(state.Rows)) {
		return store.ErrCorrupt
	}
	raw, e := readPrivate(filepath.Join(dir, item.File), int64(item.Length))
	if e != nil {
		return e
	}
	if domain.U64(len(raw)) != item.Length || sha256.Sum256(raw) != item.SHA {
		return store.ErrCorrupt
	}
	decoded, e := store.DecodeControlSnapshot(raw, item.header(), snapshotValues(item.Kind))
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(decoded, state) {
		return errors.New("snapshot state differs from source")
	}
	canonical, e := store.EncodeControlSnapshot(item.header(), decoded, level, snapshotValues(item.Kind))
	if e != nil {
		return e
	}
	if !bytes.Equal(raw, canonical) {
		return errors.New("snapshot encoding differs from declared level")
	}
	return nil
}

// VerifyControlSnapshot は候補を元WAL・最新の移管証明と再照合する。単独復旧や世代切替のAPIではない。
func (r *Repository) VerifyControlSnapshot(ctx context.Context, input string) (ControlSnapshotReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return ControlSnapshotReport{}, e
	}
	if e := r.candidatePath(input); e != nil {
		return ControlSnapshotReport{}, e
	}
	manifest, e := readCandidateManifest(input)
	if e != nil {
		return ControlSnapshotReport{}, e
	}
	proof, e := r.requireCandidateProof(ctx)
	if e != nil {
		return ControlSnapshotReport{}, e
	}
	if manifest.Site != siteID(r.site.State()) || len(manifest.Owners) != len(proof.Owners) {
		return ControlSnapshotReport{}, store.ErrCorrupt
	}
	key, e := controlAnchorKey(r.cfg.DataDir)
	if e != nil {
		return ControlSnapshotReport{}, e
	}
	defer clear(key[:])
	result := ControlSnapshotReport{ID: manifest.ID}
	names := []string{"candidate.json"}
	archiveBudget := int64(candidateLimit)
	for i, owner := range proof.Owners {
		item := manifest.Owners[i]
		if manifest.Schema == 2 {
			if e = verifyCandidateAnchor(input, manifest, item, key); e != nil {
				return ControlSnapshotReport{}, e
			}
			names = append(names, anchorFile(item))
		}
		if item.Owner != owner.Owner || item.Kind != owner.Kind || item.Sequence != owner.SourceSeq {
			return ControlSnapshotReport{}, errors.New("candidate is stale or has a different owner")
		}
		e = r.withCandidateSource(ctx, owner, func(log *store.ControlLog) error {
			h := log.HistoryHeader()
			if h.BaseSeq != 0 || h.Generation == math.MaxUint64 || uint64(item.Generation) != h.Generation+1 {
				return store.ErrCorrupt
			}
			transfer, _, err := r.loadAuditProof(ctx, owner.Owner, owner.Kind, &archiveBudget)
			if err != nil {
				return err
			}
			if transfer == nil || *transfer != item.Proof {
				return errors.New("candidate audit proof differs")
			}
			if err := r.inspectSnapshotState(owner, log.State()); err != nil {
				return err
			}
			return verifyCandidateFile(input, item, log.State(), manifest.Level)
		})
		if e != nil {
			return ControlSnapshotReport{}, e
		}
		names = append(names, item.File)
		result.Owners++
		result.Bytes += item.Length
		if result.Bytes > candidateLimit {
			return ControlSnapshotReport{}, store.ErrHistoryBudget
		}
	}
	if e = requireEntries(input, names); e != nil {
		return ControlSnapshotReport{}, fmt.Errorf("invalid candidate files: %w", e)
	}
	if e = ctx.Err(); e != nil {
		return ControlSnapshotReport{}, e
	}
	result.Verified = true
	return result, nil
}
