// 期限外の日別監査回収、保持境界日の保護、途中削除の再開を検証する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func auditReclaimFixture(t *testing.T) (Config, string, []string, []string) {
	t.Helper()
	cfg, input, m := retentionApplyFixture(t)
	if _, err := ApplyAuditRetention(context.Background(), cfg, input, postcapture.Validate); err != nil {
		t.Fatal(err)
	}
	removed, kept := []string{}, []string{}
	sink := auditSink{root: filepath.Join(cfg.DataDir, "audit")}
	defer sink.close()
	for _, o := range m.Owners {
		since := time.Unix(0, int64(o.After.Proof.Since)).UTC()
		day := time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, time.UTC)
		for _, old := range []bool{true, false} {
			at := day
			if old {
				at = day.AddDate(0, 0, -1)
			}
			entry := AuditEntry{ID: domain.NewID(), Owner: o.After.Owner, OwnerKind: o.After.Kind, Sequence: 1, Committed: at.Format(time.RFC3339Nano), ActorKind: "system", Action: "site_name_update", Fields: append([]string{}, auditActions["site_name_update"]...), Targets: []string{}}
			if o.After.Kind == "board" {
				id := o.After.Owner
				entry.Board = &id
			}
			if err := sink.put(entry); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(cfg.DataDir, "audit", o.After.Owner.String(), at.Format("20060102"))
			if old {
				removed = append(removed, path)
			} else {
				kept = append(kept, path)
			}
		}
		kept = append(kept, filepath.Join(cfg.DataDir, "audit", o.After.Owner.String(), time.Unix(0, int64(o.AfterProof.Imported)).UTC().Format("20060102")))
	}
	return cfg, input, removed, kept
}

func TestAuditReclaimRoundTrip(t *testing.T) {
	cfg, input, removed, kept := auditReclaimFixture(t)
	original := map[string][]byte{}
	for _, dir := range kept {
		for _, name := range []string{"control.current", "control-000001.wal"} {
			path := filepath.Join(dir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			original[path] = raw
		}
	}
	preview, err := ReclaimAuditDays(context.Background(), cfg, false, postcapture.Validate)
	if err != nil || preview.Applied || preview.Days != len(removed) || preview.Bytes == 0 {
		t.Fatal(preview, err)
	}
	for _, path := range removed {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("preview deleted data", err)
		}
	}
	report, err := ReclaimAuditDays(context.Background(), cfg, true, postcapture.Validate)
	if err != nil || !report.Applied || report.Days != preview.Days || report.Bytes != preview.Bytes {
		t.Fatal(report, err)
	}
	for _, path := range removed {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("expired day remains", err)
		}
	}
	for path, want := range original {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("retained day changed", path, err)
		}
	}
	report, err = ReclaimAuditDays(context.Background(), cfg, true, postcapture.Validate)
	if err != nil || report.Days != 0 {
		t.Fatal(report, err)
	}
	if _, err = ApplyAuditRetention(context.Background(), cfg, input, postcapture.Validate); err != nil {
		t.Fatal("completed retention replay after reclaim", err)
	}
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	importCandidateAudit(t, r)
	proof, err := r.VerifyAuditTransfer(context.Background())
	if err != nil || !proof.Complete {
		t.Fatal(proof, err)
	}
	output := filepath.Join(candidateParent(t), "next")
	if _, err = r.PrepareAuditRetention(context.Background(), output); err != nil {
		t.Fatal(err)
	}
}

func TestAuditReclaimCrash(t *testing.T) {
	if stage := os.Getenv("OIMO_TEST_AUDIT_RECLAIM_STAGE"); stage != "" {
		var cfg Config
		if err := json.Unmarshal([]byte(os.Getenv("OIMO_TEST_AUDIT_RECLAIM_CONFIG")), &cfg); err != nil {
			t.Fatal(err)
		}
		_, err := reclaimAuditDays(context.Background(), cfg, true, postcapture.Validate, func(s string) {
			if s == stage {
				os.Exit(77)
			}
		})
		t.Fatalf("checkpoint not reached: %v", err)
	}
	for _, stage := range []string{"audit_reclaim_intent", "audit_reclaim_plan", "audit_reclaim_rename", "audit_reclaim_unlink", "audit_reclaim_day", "audit_reclaim_plan_removed"} {
		t.Run(stage, func(t *testing.T) {
			cfg, _, removed, kept := auditReclaimFixture(t)
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestAuditReclaimCrash$")
			child.Env = append(os.Environ(), "OIMO_TEST_AUDIT_RECLAIM_STAGE="+stage, "OIMO_TEST_AUDIT_RECLAIM_CONFIG="+string(raw))
			output, err := child.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 77 {
				t.Fatalf("child: %s %v", output, err)
			}
			if r, err := OpenPostingRepository(cfg, postcapture.Validate); err == nil {
				r.Close()
				t.Fatal("pending reclaim allowed startup")
			}
			if _, err = ReclaimAuditDays(context.Background(), cfg, false, postcapture.Validate); err == nil {
				t.Fatal("pending preview accepted")
			}

			if stage == "audit_reclaim_rename" {
				names, e := os.ReadDir(filepath.Join(cfg.DataDir, auditReclaimIntent))
				if e != nil {
					t.Fatal(e)
				}
				var path string
				for _, name := range names {
					if name.IsDir() {
						path = filepath.Join(cfg.DataDir, auditReclaimIntent, name.Name(), "control-000001.wal")
					}
				}
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				bad := append([]byte(nil), raw...)
				bad[len(bad)-1] ^= 1
				if e = os.WriteFile(path, bad, 0600); e != nil {
					t.Fatal(e)
				}
				if _, e = ReclaimAuditDays(context.Background(), cfg, true, postcapture.Validate); e == nil {
					t.Fatal("modified staged file accepted")
				}
				got, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(got, bad) {
					t.Fatal("staged conflict overwritten", e)
				}
				if e = os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				} // 試験で注入した破損だけを戻す。
			}
			if stage == "audit_reclaim_plan" {
				path := filepath.Join(cfg.DataDir, auditReclaimIntent, "plan.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw[:len(raw)/2], 0600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := ReclaimAuditDays(context.Background(), cfg, true, postcapture.Validate)
			if err != nil || !report.Applied {
				t.Fatal(report, err)
			}
			for _, path := range removed {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("day remains", err)
				}
			}
			for _, path := range kept {
				if _, err := os.Stat(path); err != nil {
					t.Fatal("retained day missing", err)
				}
			}
			r, err := OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal(err)
			}
			r.Close()
		})
	}
}

func TestAuditReclaimRejectsCorruptionAndLive(t *testing.T) {
	cfg, _, removed, _ := auditReclaimFixture(t)
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReclaimAuditDays(context.Background(), cfg, true, postcapture.Validate); err == nil {
		r.Close()
		t.Fatal("live lock bypassed")
	}
	r.Close()
	path := filepath.Join(removed[len(removed)-1], "control-000001.wal")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReclaimAuditDays(context.Background(), cfg, true, postcapture.Validate); err == nil {
		t.Fatal("corrupt day reclaimed")
	}
	for _, path := range removed {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("deleted before full verification", err)
		}
	}
}

func TestAuditReclaimCancellation(t *testing.T) {
	cfg, _, removed, _ := auditReclaimFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReclaimAuditDays(ctx, cfg, true, postcapture.Validate); err == nil {
		t.Fatal("canceled reclaim accepted")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, auditReclaimIntent)); !os.IsNotExist(err) {
		t.Fatal("cancellation created intent", err)
	}
	for _, path := range removed {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}
