// 実snapshot・日別監査・deltaを使い、切替境界からの連続証明を検証する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestSnapshotAuditContinuation(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	importCandidateAudit(t, r)
	candidate := filepath.Join(candidateParent(t), "candidate")
	if _, err := r.PrepareControlSnapshot(ctx, candidate, 6); err != nil {
		t.Fatal(err)
	}
	manifest, err := readCandidateManifest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	anchor := manifest.Owners[0]
	key, err := controlAnchorKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key[:])
	persisted, err := readControlAnchor(filepath.Join(candidate, anchorFile(anchor)), manifest.Site, manifest.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	anchor = persisted.Owner

	dir := candidateParent(t)
	for _, name := range []string{"control.current", "control-000001.wal"} {
		b, err := os.ReadFile(filepath.Join(cfg.DataDir, "site", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	log, err := store.OpenControlWithValidators(dir, 1, anchor.Owner, 0, validateSiteValue, snapshotSiteValue)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { log.Close() }()
	raw, err := os.ReadFile(filepath.Join(candidate, anchor.File))
	if err != nil {
		t.Fatal(err)
	}
	if result := log.SwitchSnapshot(raw); result.Status != store.Durable {
		t.Fatal(result)
	}
	log.Close()
	if err = os.Remove(filepath.Join(dir, "control-000001.wal")); err != nil {
		t.Fatal(err)
	}
	log, err = store.OpenControlWithValidators(dir, 1, anchor.Owner, 0, validateSiteValue, snapshotSiteValue)
	if err != nil {
		t.Fatal(err)
	}
	load := func() (auditTransfer, map[domain.ID]auditStoredEntry) {
		t.Helper()
		budget := int64(64 << 20)
		proof, entries, err := r.loadAuditProof(ctx, anchor.Owner, "site", &budget)
		if err != nil || proof == nil {
			t.Fatal(err)
		}
		return *proof, entries
	}
	verify := func(a candidateOwner, p auditTransfer, e map[domain.ID]auditStoredEntry) (AuditTransferOwner, error) {
		budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
		return verifySnapshotAudit(ctx, log, a, p, e, &budget)
	}
	proof, entries := load()
	if result, err := verify(anchor, proof, entries); err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	var site siteState
	if err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		t.Fatal(err)
	}
	site.Name = "snapshot後の更新"
	frame, err := controlFrame(r.site.State(), domain.NewID(), domain.Time(time.Now().UnixNano()), "site_name_update", []store.Mutation{mutation("site", "state", site, nil)}, []string{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []*store.ControlLog{r.site, log} {
		if result := target.Append(frame); result.Status != store.Durable {
			t.Fatal(result)
		}
	}
	if result, err := verify(anchor, proof, entries); err != nil || result.Complete || result.VerifiedSeq != anchor.Sequence {
		t.Fatal("stale proof", result, err)
	}
	importCandidateAudit(t, r)
	proof, entries = load()
	if result, err := verify(anchor, proof, entries); err != nil || !result.Complete {
		t.Fatal("delta proof", result, err)
	}
	for _, name := range []string{"kind", "snapshot_hash", "generation", "boundary", "source_hash", "retention", "missing", "extra", "changed"} {
		t.Run(name, func(t *testing.T) {
			a, p := anchor, proof
			copied := map[domain.ID]auditStoredEntry{}
			for id, e := range entries {
				copied[id] = e
			}
			switch name {
			case "kind":
				a.Kind = "unknown"
			case "snapshot_hash":
				a.SHA[0] ^= 1
			case "generation":
				a.Generation++
			case "boundary":
				a.Proof.Sequence++
			case "source_hash":
				p.SourceHash[0] ^= 1
			case "retention":
				p.Since++
			case "missing":
				for id := range copied {
					delete(copied, id)
					break
				}
			case "extra":
				for _, e := range copied {
					id := domain.NewID()
					e.Summary.ID = id
					copied[id] = e
					break
				}
			case "changed":
				for id, e := range copied {
					e.Summary.Targets = []string{domain.NewID().String()}
					copied[id] = e
					break
				}
			}
			if _, err := verify(a, p, copied); err == nil {
				t.Fatal("invalid continuation accepted")
			}
		})
	}
	budget := store.HistoryBudget{Bytes: 63, Frames: 100}
	if _, err = verifySnapshotAudit(ctx, log, anchor, proof, entries, &budget); !errors.Is(err, store.ErrHistoryBudget) {
		t.Fatal("budget", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	budget = store.HistoryBudget{Bytes: 64 << 20, Frames: 100}
	if _, err = verifySnapshotAudit(canceled, log, anchor, proof, entries, &budget); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel", err)
	}
}
