// 保持下限の実適用・起動禁止・別プロセス中断からの再開を検証する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/postcapture"
)

func retentionApplyFixture(t *testing.T) (Config, string, retentionCandidate) {
	t.Helper()
	cfg, _ := reclaimedFixture(t)
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(candidateParent(t), "retention")
	if _, err = r.PrepareAuditRetention(context.Background(), input); err != nil {
		r.Close()
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := readRetentionCandidate(cfg, input)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, input, m
}

func TestAuditRetentionApplyRoundTrip(t *testing.T) {
	cfg, input, m := retentionApplyFixture(t)
	unchanged := map[string][]byte{}
	for _, o := range m.Owners {
		for _, name := range []string{"control.current", "control-000001.wal", "control-000002.snap", "control-000002.wal"} {
			path := filepath.Join(controlOwnerPath(cfg.DataDir, o.Before.Kind, o.Before.Owner), name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			unchanged[path] = raw
		}
	}
	for range 2 {
		report, err := ApplyAuditRetention(context.Background(), cfg, input, postcapture.Validate)
		if err != nil || !report.Applied {
			t.Fatal(report, err)
		}
	}
	for path, want := range unchanged {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("source changed", path, err)
		}
	}
	// 更新後の境界でも、残した旧WALを正しく照合・回収できる。
	if _, err := ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate); err != nil {
		t.Fatal(err)
	}
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range m.Owners {
		if r.anchors[o.After.Owner] != o.After {
			r.Close()
			t.Fatal("boundary not applied")
		}
	}
	importCandidateAudit(t, r)
	var board retentionOwner
	for _, o := range m.Owners {
		if o.Before.Kind == "board" {
			board = o
		}
	}
	form := formServer(t, r, m.Site, board.Before.Owner)
	request := url.Values{"bbs": {"activation"}, "subject": {"期限更新後"}, "MESSAGE": {"投稿本文"}, "oimo_request_id": {"retention-apply-request-001"}}
	first, err := sendForm(form, request)
	form.Close()
	if err != nil || !first.Accepted {
		r.Close()
		t.Fatal(first, err)
	}
	importCandidateAudit(t, r)
	nextInput := filepath.Join(candidateParent(t), "next")
	if _, err = r.PrepareAuditRetention(context.Background(), nextInput); err != nil {
		r.Close()
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyAuditRetention(context.Background(), cfg, input, postcapture.Validate); err == nil {
		t.Fatal("stale candidate reapplied")
	}
	if _, err = ApplyAuditRetention(context.Background(), cfg, nextInput, postcapture.Validate); err != nil {
		t.Fatal(err)
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	form = formServer(t, r, m.Site, board.Before.Owner)
	defer form.Close()
	duplicate, err := sendForm(form, request)
	if err != nil || !duplicate.Duplicate || duplicate.Key != first.Key {
		t.Fatal(duplicate, err)
	}
	if proof, err := r.VerifyAuditTransfer(context.Background()); err != nil || !proof.Complete {
		t.Fatal(proof, err)
	}
}

func TestAuditRetentionApplyCrash(t *testing.T) {
	if stage := os.Getenv("OIMO_TEST_RETENTION_STAGE"); stage != "" {
		var cfg Config
		if err := json.Unmarshal([]byte(os.Getenv("OIMO_TEST_RETENTION_CONFIG")), &cfg); err != nil {
			t.Fatal(err)
		}
		_, err := applyAuditRetention(context.Background(), cfg, os.Getenv("OIMO_TEST_RETENTION_INPUT"), postcapture.Validate, func(s string) {
			if s == stage {
				os.Exit(77)
			}
		})
		t.Fatalf("checkpoint not reached: %v", err)
	}
	for _, stage := range []string{"retention_intent", "retention_proof", "retention_anchor_sync", "retention_anchor_rename", "retention_owner", "retention_validated"} {
		t.Run(stage, func(t *testing.T) {
			cfg, input, m := retentionApplyFixture(t)
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestAuditRetentionApplyCrash$")
			child.Env = append(os.Environ(), "OIMO_TEST_RETENTION_STAGE="+stage, "OIMO_TEST_RETENTION_CONFIG="+string(raw), "OIMO_TEST_RETENTION_INPUT="+input)
			output, err := child.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 77 {
				t.Fatalf("child: %s %v", output, err)
			}
			if r, err := OpenPostingRepository(cfg, postcapture.Validate); err == nil {
				r.Close()
				t.Fatal("partial renewal allowed startup")
			}
			if stage == "retention_anchor_sync" {
				intents, e := filepath.Glob(filepath.Join(cfg.DataDir, ".audit-retention-*"))
				if e != nil || len(intents) != 1 {
					t.Fatal(intents, e)
				}
				temp := filepath.Join(intents[0], m.Owners[0].Before.Owner.String()+".anchor")
				correct, e := os.ReadFile(temp)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(temp, []byte("wrong-prefix"), 0600); e != nil {
					t.Fatal(e)
				}
				if _, e = ApplyAuditRetention(context.Background(), cfg, input, postcapture.Validate); e == nil {
					t.Fatal("conflicting temporary anchor accepted")
				}
				got, e := os.ReadFile(temp)
				if e != nil || string(got) != "wrong-prefix" {
					t.Fatal("temporary conflict overwritten", e)
				}
				// 注入した異内容を一致する途中prefixに戻し、補完も検証する。
				if e = os.WriteFile(temp, correct[:len(correct)/2], 0600); e != nil {
					t.Fatal(e)
				}
			}
			if stage == "retention_intent" {
				// 証明追記中の不完全末尾を注入する。再開はaudit所有単位だけを復旧する。
				o := m.Owners[0]
				day := time.Unix(0, int64(m.Created)).UTC().Format("20060102")
				path := filepath.Join(cfg.DataDir, "audit", o.Before.Owner.String(), day, "control-000001.wal")
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte{1, 2, 3})
				closeErr := f.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			for range 2 {
				report, err := ApplyAuditRetention(context.Background(), cfg, input, postcapture.Validate)
				if err != nil || !report.Applied {
					t.Fatal(report, err)
				}
			}
			r, err := OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal(err)
			}
			importCandidateAudit(t, r)
			if proof, err := r.VerifyAuditTransfer(context.Background()); err != nil || !proof.Complete {
				r.Close()
				t.Fatal(proof, err)
			}
			r.Close()
		})
	}
}

func TestAuditRetentionApplyRejectsChangedSourceAndLock(t *testing.T) {
	cfg, input, _ := retentionApplyFixture(t)
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyAuditRetention(context.Background(), cfg, input, postcapture.Validate); err == nil {
		r.Close()
		t.Fatal("live lock bypassed")
	}
	if _, err = r.CreateBoard(context.Background(), "later", "追加"); err != nil {
		r.Close()
		t.Fatal(err)
	}
	r.Close()
	if _, err = ApplyAuditRetention(context.Background(), cfg, input, postcapture.Validate); err == nil {
		t.Fatal("changed owners accepted")
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("rejection left intent", err)
	}
	r.Close()
}
