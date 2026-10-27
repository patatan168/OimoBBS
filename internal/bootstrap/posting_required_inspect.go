// 必須原本回収のreader境界と署名metadataを製品の非変更検査へ接続する。
package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

var postingJournalFile = regexp.MustCompile(`^control-([0-9]{6,20})\.(wal|snap)$`)

// inspectPostingJournalDirectory はsnapshot/旧世代と既知回収intentを許し、未知fileと非私有fileを拒否する。
func inspectPostingJournalDirectory(path string) error {
	names, e := boundedAuditNames(path, 4096)
	if e != nil {
		return e
	}
	m, e := store.InspectControlManifest(path)
	if e != nil {
		return e
	}
	intent := false
	for _, name := range names {
		intent = intent || name == ".optional-prune.snapshot"
	}
	for _, name := range names {
		if !knownPostingJournalFile(name, m, intent) {
			return errors.New("unknown posting journal file")
		}
		if e = privatePath(filepath.Join(path, name), false); e != nil {
			return e
		}
	}
	return nil
}

// knownPostingJournalFile はcurrent参照と回収intentに付随する世代だけを許す。
func knownPostingJournalFile(name string, m store.ControlManifest, intent bool) bool {
	if name == "control.current" || name == m.Delta.File || name == ".optional-prune.snapshot" {
		return true
	}
	if m.Snapshot != nil && name == m.Snapshot.File {
		return true
	}
	if !intent {
		return false
	}
	return postingPruneGeneration(name, uint64(m.Generation))
}

// postingPruneGeneration は回収途中の旧世代と切替候補の直後世代だけを識別する。
func postingPruneGeneration(name string, current uint64) bool {
	match := postingJournalFile.FindStringSubmatch(name)
	if match == nil {
		return false
	}
	generation, e := strconv.ParseUint(match[1], 10, 64)
	return e == nil && generation != 0 && (generation <= current || generation-1 == current)
}

// recoveryBodyCarries は回収正本に束縛された完成carryだけを新しい板復旧へ渡す。
func (b *postingBoard) recoveryBodyCarries(proofs map[uint64]app.BodyReclamation) (map[uint64]app.BodyCarry, error) {
	result := map[uint64]app.BodyCarry{}
	for key, proof := range proofs {
		log := b.deletions[key]
		if log == nil {
			return nil, app.ErrEvidenceGap
		}
		carry, e := b.boundBodyCarry(log.State(), proof)
		if e != nil {
			return nil, e
		}
		if carry != nil {
			result[key] = *carry
		}
	}
	return result, nil
}

// inspectRequiredPostingJournals はcheck中に原本回収を再開せず、署名とreader境界だけを検査する。
func inspectRequiredPostingJournals(cfg Config, site siteState, boards []persistedBoard) error {
	if e := inspectPostingEvidenceOwners(cfg, boards); e != nil {
		return e
	}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	for _, b := range boards {
		if e = inspectRequiredBoardJournals(cfg, site, b, key); e != nil {
			return e
		}
	}
	return nil
}

// inspectPostingEvidenceOwners は保存済み原本の所有者が現在の板集合に含まれるか検査する。
func inspectPostingEvidenceOwners(cfg Config, boards []persistedBoard) error {
	known := make(map[domain.ID]bool, len(boards))
	for _, b := range boards {
		known[b.info.ID] = true
	}
	owners, e := childIDs(filepath.Join(cfg.DataDir, "evidence"))
	if e != nil {
		return e
	}
	for _, id := range owners {
		if !known[id] {
			return errors.New("evidence has no active board")
		}
	}
	return nil
}

// inspectRequiredBoardJournals は板の日別原本を変更せず検査する。
func inspectRequiredBoardJournals(cfg Config, site siteState, b persistedBoard, key ed25519.PrivateKey) error {
	if e := inspectBodyCarryRetirementAnchors(cfg, site, b, key.Public().(ed25519.PublicKey)); e != nil {
		return e
	}
	if e := inspectRequiredCheckpointAnchors(cfg, site, b, key); e != nil {
		return e
	}
	root := filepath.Join(cfg.DataDir, "evidence", b.info.ID.String())
	days, e := postingNames(root)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	for _, day := range days {
		path := filepath.Join(root, fmt.Sprint(day))
		if e = inspectPostingJournalDirectory(path); e != nil {
			return e
		}
		inspection, e := evidence.InspectJournalConcurrent(path, b.info.ID, day, 10, key, app.PostingValidatorConcurrent(strictjson.Validate))
		if e != nil {
			return e
		}
		if inspection.MinimumReader > site.MinimumReader {
			return errors.New("required retirement exceeds site minimum reader")
		}
		if e = checkRequiredJournalBoundary(inspection, site.MinimumReader >= 45, domain.Time(time.Now().UnixNano())); e != nil {
			return e
		}
	}
	return nil
}

// checkRequiredJournalBoundary はsnapshot/旧世代回収を再開する前にreaderと実回収時計床を照合する。
func checkRequiredJournalBoundary(v evidence.JournalInspection, enabled bool, now domain.Time) error {
	if v.RequiredRetirements != 0 && !enabled {
		return errors.New("required retirement requires reader 45")
	}
	if now < v.RequiredFloor {
		return evidence.ErrRetirementClock
	}
	return nil
}
