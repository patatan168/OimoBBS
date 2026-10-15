// 保持下限の前後1ns、旧prefixの欠落拒否、MAC候補の再照合と無変更性を検証する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// retentionBoundaryFixture は保持境界前後の実WALと、境界を跨ぐsnapshot/deltaを作る。
func retentionBoundaryFixture(t *testing.T) (*store.ControlLog, candidateOwner, auditTransfer, map[domain.ID]auditStoredEntry, time.Time) {
	t.Helper()
	at := time.Now().UTC().Add(-time.Second)
	cutoff := at.Add(-auditRetention)
	owner := domain.NewID()
	h := store.Header{Kind: 2, Owner: owner, Generation: 1}
	dir := filepath.Join(candidateParent(t), "control")
	proof := auditTransfer{Schema: 1, Kind: "source_transfer", Owner: owner, OwnerKind: "board", Generation: 1, Since: domain.Time(cutoff.Add(-time.Hour).UnixNano()), Imported: domain.Time(at.Add(-time.Hour).UnixNano())}
	entries := map[domain.ID]auditStoredEntry{}
	var log *store.ControlLog
	var anchor candidateOwner
	for i := 1; i <= 3; i++ {
		state := store.ControlState{}
		if log != nil {
			state = log.State()
		}
		committed := domain.Time(cutoff.Add(time.Duration(i - 2)).UnixNano())
		value := struct {
			Last domain.U64 `json:"last_reserved_key"`
		}{domain.U64(i - 1)}
		raw, err := controlFrame(state, domain.NewID(), committed, "board_settings_update", []store.Mutation{mutation("key_watermark", "thread", value, nil)}, []string{})
		if err != nil {
			t.Fatal(err)
		}
		if log == nil {
			log, err = store.CreateControl(dir, h, raw, validateBoardValue)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { log.Close() })
		} else if result := log.Append(raw); result.Status != store.Durable {
			t.Fatal(result)
		}
		frame, _, err := store.ReadFrame(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		var op store.ControlOperation
		if err = strictjson.Decode(frame.Records[0].JSON, &op); err != nil {
			t.Fatal(err)
		}
		entry, ok := auditSummary(owner, "board", frame.Records[0], op)
		if !ok {
			t.Fatal("missing summary")
		}
		entries[entry.ID] = auditStoredEntry{1, "control_summary", committed + domain.Time(auditRetention), entry}
		if err = proof.advance(frame.Records[0], op, &entry); err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			if err = log.Close(); err != nil {
				t.Fatal(err)
			}
			log, err = store.OpenControlWithValidators(dir, 2, owner, 0, validateBoardValue, snapshotBoardValue)
			if err != nil {
				t.Fatal(err)
			}
			next := h
			next.Generation = 2
			next.BaseSeq = 2
			snapshot, err := store.EncodeControlSnapshot(next, log.State(), 6, snapshotBoardValue)
			if err != nil {
				t.Fatal(err)
			}
			anchor = candidateOwner{Owner: owner, Kind: "board", Generation: 2, Sequence: 2, Rows: 1, File: "board-" + owner.String() + ".snap", Length: domain.U64(len(snapshot)), SHA: sha256.Sum256(snapshot), Proof: proof}
			if result := log.SwitchSnapshot(snapshot); result.Status != store.Durable {
				t.Fatal(result)
			}
		}
	}
	proof.Imported = domain.Time(at.Add(-time.Minute).UnixNano())
	return log, anchor, proof, entries, at
}

func TestAuditRetentionBoundary(t *testing.T) {
	log, anchor, proof, entries, at := retentionBoundaryFixture(t)
	budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	next, latest, err := renewAuditBoundary(context.Background(), log, anchor, proof, entries, at, &budget)
	if err != nil {
		t.Fatal(err)
	}
	if next.Proof.Entries != 1 || latest.Entries != 2 || next.Proof.Since != domain.Time(at.Add(-auditRetention).UnixNano()) {
		t.Fatal("cutoff equality or counts", next.Proof, latest)
	}
	if next.Proof.SourceHash != anchor.Proof.SourceHash || latest.SourceHash != proof.SourceHash || latest.Sequence != proof.Sequence || next.SHA != anchor.SHA {
		t.Fatal("source identity changed")
	}
	budget = store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	repeated, repeatedProof, err := renewAuditBoundary(context.Background(), log, next, latest, entries, at, &budget)
	if err != nil || repeated != next || repeatedProof != latest {
		t.Fatal("same cutoff changed", err)
	}
}

func TestAuditRetentionRejectsMissingExpiredPrefix(t *testing.T) {
	log, anchor, proof, entries, at := retentionBoundaryFixture(t)
	for id, entry := range entries {
		if entry.Summary.Sequence == 1 {
			delete(entries, id)
		}
	}
	budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	if _, _, err := renewAuditBoundary(context.Background(), log, anchor, proof, entries, at, &budget); err == nil {
		t.Fatal("new cutoff concealed missing expired entry")
	}
}

func TestAuditRetentionRejectsClockBudgetAndStaleProof(t *testing.T) {
	log, anchor, proof, entries, at := retentionBoundaryFixture(t)
	for _, when := range []time.Time{time.Now().Add(time.Hour), at.Add(-2 * time.Hour)} {
		budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
		if _, _, err := renewAuditBoundary(context.Background(), log, anchor, proof, entries, when, &budget); err == nil {
			t.Fatal("invalid clock accepted")
		}
	}
	budget := store.HistoryBudget{}
	if _, _, err := renewAuditBoundary(context.Background(), log, anchor, proof, entries, at, &budget); err == nil {
		t.Fatal("budget bypassed")
	}
	budget = store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	if _, _, err := renewAuditBoundary(context.Background(), log, anchor, anchor.Proof, entries, at, &budget); err == nil {
		t.Fatal("stale proof accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := renewAuditBoundary(ctx, log, anchor, proof, entries, at, &budget); err == nil {
		t.Fatal("canceled renewal accepted")
	}
}

func TestAuditRetentionCandidate(t *testing.T) {
	cfg, m := reclaimedFixture(t)
	if _, err := ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate); err != nil {
		t.Fatal(err)
	}
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	original := map[string][]byte{}
	err = filepath.WalkDir(cfg.DataDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			original[path] = raw
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(candidateParent(t), "retention")
	report, err := r.PrepareAuditRetention(context.Background(), output)
	if err != nil || !report.Verified || report.Applied || report.Owners != len(m.Owners) {
		t.Fatal(report, err)
	}
	checked, err := r.VerifyAuditRetention(context.Background(), output)
	if err != nil || !reflect.DeepEqual(report, checked) {
		t.Fatal(checked, err)
	}
	for path, want := range original {
		got, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("source changed", path, e)
		}
	}
	if _, err = r.PrepareAuditRetention(context.Background(), output); err == nil {
		t.Fatal("existing candidate overwritten")
	}
	path := filepath.Join(output, "retention.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env anchorEnvelope
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.MAC[0] ^= 1
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.VerifyAuditRetention(context.Background(), output); err == nil {
		t.Fatal("invalid MAC accepted")
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.CreateBoard(context.Background(), "newowner", "追加板"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.VerifyAuditRetention(context.Background(), output); err == nil {
		t.Fatal("changed owner set accepted")
	}
}

func TestAuditRetentionAllExpired(t *testing.T) {
	log, anchor, proof, entries, at := retentionBoundaryFixture(t)
	budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	next, latest, err := renewAuditBoundary(context.Background(), log, anchor, proof, entries, at.Add(2*time.Nanosecond), &budget)
	if err != nil || next.Proof.Entries != 0 || latest.Entries != 0 || next.Proof.SummaryHash != (domain.Hash{}) || latest.SourceHash != proof.SourceHash {
		t.Fatal(next.Proof, latest, err)
	}
}
