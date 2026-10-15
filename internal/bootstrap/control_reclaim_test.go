// 旧WAL回収の無変更プレビュー・中断再開・復旧と不整合拒否を検証する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"oimobbs/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"oimobbs/internal/postcapture"
)

func reclaimedFixture(t *testing.T) (Config, controlCandidate) {
	t.Helper()
	cfg, input, m := activationFixture(t)
	if _, err := ActivateControlSnapshot(context.Background(), cfg, input, postcapture.Validate); err != nil {
		t.Fatal(err)
	}
	return cfg, m
}

func TestControlReclaimRoundTrip(t *testing.T) {
	cfg, m := reclaimedFixture(t)
	report, err := ReclaimControlWAL(context.Background(), cfg, false, postcapture.Validate)
	if err != nil || report.Files != len(m.Owners) || report.Bytes == 0 || report.Applied {
		t.Fatalf("preview: %+v %v", report, err)
	}
	for _, o := range m.Owners {
		if _, err := os.Stat(filepath.Join(controlOwnerPath(cfg.DataDir, o.Kind, o.Owner), "control-000001.wal")); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate)
	if err != nil || applied.Files != report.Files || applied.Bytes != report.Bytes || !applied.Applied {
		t.Fatalf("apply: %+v %v", applied, err)
	}
	for _, o := range m.Owners {
		if _, err := os.Stat(filepath.Join(controlOwnerPath(cfg.DataDir, o.Kind, o.Owner), "control-000001.wal")); !os.IsNotExist(err) {
			t.Fatal("old WAL remains", err)
		}
	}
	again, err := ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate)
	if err != nil || again.Files != 0 || !again.Applied {
		t.Fatalf("repeat: %+v %v", again, err)
	}
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	importCandidateAudit(t, r)
	if proof, err := r.VerifyAuditTransfer(context.Background()); err != nil || !proof.Complete {
		t.Fatal("audit after reclaim", err)
	}
	if _, err = r.CreateBoard(context.Background(), "aftergc", "回収後の追加"); err != nil {
		t.Fatal(err)
	}
}

func TestControlReclaimRejectsCorruptionBeforeDeleting(t *testing.T) {
	for _, target := range []string{"retired", "snapshot", "anchor", "pending"} {
		t.Run(target, func(t *testing.T) {
			cfg, m := reclaimedFixture(t)
			o := m.Owners[len(m.Owners)-1]
			dir := controlOwnerPath(cfg.DataDir, o.Kind, o.Owner)
			name := map[string]string{"retired": "control-000001.wal", "snapshot": "control-000002.snap", "anchor": "control-000002.anchor.json", "pending": "control-000003.wal"}[target]
			path := filepath.Join(dir, name)
			if target == "pending" {
				if err := os.WriteFile(path, []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw[len(raw)-1] ^= 1
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate); err == nil {
				t.Fatal("corruption accepted")
			}
			for _, owner := range m.Owners {
				if _, err := os.Stat(filepath.Join(controlOwnerPath(cfg.DataDir, owner.Kind, owner.Owner), "control-000001.wal")); err != nil {
					t.Fatal("partial deletion before verification", err)
				}
			}
		})
	}
}

// unlinkとdirectory Syncのそれぞれでプロセスを停止して、残りだけ回収できることを確認する。
func TestControlReclaimCrash(t *testing.T) {
	if stage := os.Getenv("OIMO_TEST_RECLAIM_STAGE"); stage != "" {
		var cfg Config
		if err := json.Unmarshal([]byte(os.Getenv("OIMO_TEST_RECLAIM_CONFIG")), &cfg); err != nil {
			t.Fatal(err)
		}
		_, err := reclaimControlWAL(context.Background(), cfg, true, postcapture.Validate, func(s string) {
			if s == stage {
				os.Exit(77)
			}
		})
		t.Fatalf("checkpoint not reached: %v", err)
	}
	for _, stage := range []string{"reclaim_unlink", "reclaim_directory_sync"} {
		t.Run(stage, func(t *testing.T) {
			cfg, m := reclaimedFixture(t)
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestControlReclaimCrash$")
			child.Env = append(os.Environ(), "OIMO_TEST_RECLAIM_STAGE="+stage, "OIMO_TEST_RECLAIM_CONFIG="+string(raw))
			output, err := child.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 77 {
				t.Fatalf("child: %s %v", output, err)
			}
			r, err := OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal("partial reclaim blocked recovery", err)
			}
			r.Close()
			report, err := ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate)
			if err != nil || report.Files != len(m.Owners)-1 {
				t.Fatalf("resume: %+v %v", report, err)
			}
		})
	}
}

func TestControlReclaimRefusesLiveAndCanceled(t *testing.T) {
	cfg, _ := reclaimedFixture(t)
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate); err == nil {
		r.Close()
		t.Fatal("live reclaim accepted")
	}
	r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = ReclaimControlWAL(ctx, cfg, true, postcapture.Validate); err == nil {
		t.Fatal("canceled reclaim accepted")
	}
	report, err := ReclaimControlWAL(context.Background(), cfg, false, postcapture.Validate)
	if err != nil || report.Files != 2 {
		t.Fatalf("files changed: %+v %v", report, err)
	}
}

func TestControlReclaimPreservesPostingAndRejectsStaleAudit(t *testing.T) {
	cfg, m := reclaimedFixture(t)
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, r, m.Site, m.Owners[1].Owner)
	request := url.Values{"bbs": {"activation"}, "subject": {"回収前のスレ"}, "MESSAGE": {"本文"}, "oimo_request_id": {"control-reclaim-request-001"}}
	first, err := sendForm(form, request)
	form.Close()
	if err != nil || !first.Accepted {
		r.Close()
		t.Fatal(first, err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate); err == nil {
		t.Fatal("unimported delta reclaimed")
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	importCandidateAudit(t, r)
	r.Close()
	current := map[string][]byte{}
	for _, o := range m.Owners {
		for _, name := range []string{"control.current", "control-000002.snap", "control-000002.wal", "control-000002.anchor.json"} {
			path := filepath.Join(controlOwnerPath(cfg.DataDir, o.Kind, o.Owner), name)
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			current[path] = raw
		}
	}
	if _, err = ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate); err != nil {
		t.Fatal(err)
	}
	for path, want := range current {
		got, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("active files changed", path, e)
		}
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	form = formServer(t, r, m.Site, m.Owners[1].Owner)
	defer form.Close()
	duplicate, err := sendForm(form, request)
	if err != nil || !duplicate.Duplicate || duplicate.Key != first.Key {
		t.Fatal(duplicate, err)
	}
	request.Set("oimo_request_id", "control-reclaim-request-002")
	created, err := sendForm(form, request)
	if err != nil || !created.Accepted || created.Key <= first.Key {
		t.Fatal(created, err)
	}
}

func TestRetiredControlBounds(t *testing.T) {
	cfg, m := reclaimedFixture(t)
	a := m.Owners[0]
	dir := controlOwnerPath(cfg.DataDir, a.Kind, a.Owner)
	for _, budget := range []store.HistoryBudget{{Bytes: 63, Frames: 200000}, {Bytes: 64 << 20, Frames: 0}} {
		if _, err := inspectRetiredControl(context.Background(), dir, a, &budget); err == nil {
			t.Fatal("budget bypassed")
		}
	}
	path := filepath.Join(dir, "control-000001.wal")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 完全な元WALの後ろに未完frameがある場合も、切り捨てず拒否する。
	if err = os.WriteFile(path, append(raw, 1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReclaimControlWAL(context.Background(), cfg, true, postcapture.Validate); err == nil {
		t.Fatal("incomplete tail reclaimed")
	}
	got, err := os.ReadFile(path)
	if err != nil || len(got) != len(raw)+1 {
		t.Fatal("tail repaired", err)
	}
}
