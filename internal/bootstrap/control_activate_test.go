package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"oimobbs/internal/postcapture"
)

// activationFixture は実CLIと同じ版更新・監査追従・候補作成を行う。
func activationFixture(t *testing.T) (Config, string, controlCandidate) {
	t.Helper()
	cfg, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	if _, err := r.CreateBoard(ctx, "activation", "切替試験"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if report, err := r.EnableControlSnapshots(ctx); err != nil || !report.AuditComplete {
			t.Fatalf("enable: %+v %v", report, err)
		}
	}
	input := filepath.Join(candidateParent(t), "candidate")
	if _, err := r.PrepareControlSnapshot(ctx, input, 6); err != nil {
		t.Fatal(err)
	}
	m, err := readCandidateManifest(input)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, input, m
}

// TestControlActivationCrash は別プロセスの即時終了から同じ候補を再開する。
func TestControlActivationCrash(t *testing.T) {
	if stage := os.Getenv("OIMO_TEST_ACTIVATION_STAGE"); stage != "" {
		var cfg Config
		if err := json.Unmarshal([]byte(os.Getenv("OIMO_TEST_ACTIVATION_CONFIG")), &cfg); err != nil {
			t.Fatal(err)
		}
		_, err := activateControlSnapshot(context.Background(), cfg, os.Getenv("OIMO_TEST_ACTIVATION_INPUT"), postcapture.Validate, func(s string) {
			if s == stage {
				os.Exit(77)
			}
		})
		t.Fatalf("checkpoint not reached: %v", err)
	}
	for _, stage := range []string{"activation_intent", "activation_anchor", "activation_current", "activation_owner", "activation_validated"} {
		t.Run(stage, func(t *testing.T) {
			cfg, input, m := activationFixture(t)
			originals := map[string][]byte{}
			for _, o := range m.Owners {
				p := filepath.Join(controlOwnerPath(cfg.DataDir, o.Kind, o.Owner), "control-000001.wal")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				originals[p] = b
			}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestControlActivationCrash$")
			child.Env = append(os.Environ(), "OIMO_TEST_ACTIVATION_STAGE="+stage, "OIMO_TEST_ACTIVATION_CONFIG="+string(raw), "OIMO_TEST_ACTIVATION_INPUT="+input)
			output, err := child.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 77 {
				t.Fatalf("child: %s %v", output, err)
			}
			if r, err := OpenPostingRepository(cfg, postcapture.Validate); err == nil {
				r.Close()
				t.Fatal("unfinished activation allowed startup")
			}
			if stage == "activation_anchor" { // snapshot書込み途中の一致prefixも補完する。
				o := m.Owners[0]
				b, err := os.ReadFile(filepath.Join(input, o.File))
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(controlOwnerPath(cfg.DataDir, o.Kind, o.Owner), "control-000002.snap")
				if err := writeNew(target, []byte("conflicting candidate")); err != nil {
					t.Fatal(err)
				}
				if _, err := ActivateControlSnapshot(context.Background(), cfg, input, postcapture.Validate); err == nil {
					t.Fatal("conflicting pending file accepted")
				}
				got, err := os.ReadFile(target)
				if err != nil || string(got) != "conflicting candidate" {
					t.Fatal("pending file overwritten", err)
				}
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				} // 試験で注入した異内容だけを除去する。
				if err := writeNew(target, b[:len(b)/2]); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				report, err := ActivateControlSnapshot(context.Background(), cfg, input, postcapture.Validate)
				if err != nil || !report.Activated {
					t.Fatalf("activate: %+v %v", report, err)
				}
			}
			r, err := OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.anchors) != len(m.Owners) {
				t.Fatal("missing active owners")
			}
			r.Close()
			for p, want := range originals {
				got, err := os.ReadFile(p)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("old WAL changed", err)
				}
			}
		})
	}
}

func TestControlActivationRejectsChangedCandidate(t *testing.T) {
	cfg, input, m := activationFixture(t)
	path := filepath.Join(input, m.Owners[0].File)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ActivateControlSnapshot(context.Background(), cfg, input, postcapture.Validate); err == nil {
		t.Fatal("changed candidate accepted")
	}
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.anchors) != 0 {
		t.Fatal("invalid candidate changed active generation")
	}
}

func TestControlActivationRejectsStaleSource(t *testing.T) {
	cfg, input, _ := activationFixture(t)
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.CreateBoard(context.Background(), "later", "候補作成後"); err != nil {
		r.Close()
		t.Fatal(err)
	}
	if _, err = r.EnableControlSnapshots(context.Background()); err != nil {
		r.Close()
		t.Fatal(err)
	}
	// 稼働中は排他で拒否する。
	if _, err = ActivateControlSnapshot(context.Background(), cfg, input, postcapture.Validate); err == nil {
		r.Close()
		t.Fatal("live activation accepted")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ActivateControlSnapshot(context.Background(), cfg, input, postcapture.Validate); err == nil {
		t.Fatal("stale source accepted")
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.anchors) != 0 {
		t.Fatal("stale source activated")
	}
}

func TestControlActivationRequiresEnabledVersion(t *testing.T) {
	cfg, r := adminFixture(t)
	importCandidateAudit(t, r)
	input := filepath.Join(candidateParent(t), "candidate")
	if _, err := r.PrepareControlSnapshot(context.Background(), input, 6); err != nil {
		r.Close()
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateControlSnapshot(context.Background(), cfg, input, postcapture.Validate); err == nil {
		t.Fatal("old reader version activated")
	}
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.anchors) != 0 {
		t.Fatal("version gate changed current")
	}
}
