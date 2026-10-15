// 完成ペアの署名認証・順序・正本喪失後の中断再開と誤配置拒否を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

func TestBackupPairReclamation(t *testing.T) {
	cfg, base := backupFixture(t)
	parent := filepath.Dir(base)
	ctx := context.Background()
	trust := filepath.Join(parent, "trust.json")
	if _, e := ExportBackupTrust(ctx, cfg, trust); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	clock := func() time.Time { return now }
	makePair := func(name string) (string, string, string) {
		t.Helper()
		body, keys, plan := filepath.Join(parent, name+"-body"), filepath.Join(parent, name+"-keys"), filepath.Join(parent, name+"-plan.json")
		if _, e := captureOfflineBackup(ctx, cfg, body, clock, func(string) {}); e != nil {
			t.Fatal(e)
		}
		if _, e := exportBackupKeys(ctx, cfg, body, keys, clock, func(string) {}); e != nil {
			t.Fatal(e)
		}
		r, e := planBackupPairReclamation(ctx, cfg, body, keys, trust, plan, clock)
		if e != nil || !r.Planned || r.Body == nil || r.Keys == nil || r.Body.ID != r.Keys.ID || r.RestoreReady {
			t.Fatal(r, e)
		}
		if _, e = planBackupPairReclamation(ctx, cfg, body, keys, trust, plan, clock); e == nil {
			t.Fatal("existing plan overwritten")
		}
		return body, keys, plan
	}
	body, keys, plan := makePair("basic")
	pairs := [][3]string{}
	for _, name := range []string{"body-file", "body-retired", "body-removed", "keys-file", "retired"} {
		b, k, p := makePair(name)
		pairs = append(pairs, [3]string{b, k, p})
	}
	if e := os.Rename(cfg.DataDir, cfg.DataDir+"-offline"); e != nil {
		t.Fatal(e)
	}
	r, e := reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(string) error { return nil })
	if e != nil || r.Applied || r.Expired || r.BodyRemoved {
		t.Fatal(r, e)
	}
	lock, e := platform.Lock(parent)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(string) error { return nil }); e == nil {
		t.Fatal("parent lock bypassed")
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	now = now.Add(25 * time.Hour)
	if e = os.WriteFile(filepath.Join(keys, "unknown"), []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(string) error { return nil }); e == nil {
		t.Fatal("unknown key file ignored")
	}
	if _, e = os.Stat(filepath.Join(body, "manifest.json")); e != nil {
		t.Fatal("body changed before keys preflight", e)
	}
	if e = os.Remove(filepath.Join(keys, "unknown")); e != nil {
		t.Fatal(e)
	}
	if _, e = reclaimBackupPair(ctx, filepath.Join(parent, "absent"), keys, trust, plan, true, clock, func(string) error { return nil }); e == nil {
		t.Fatal("unbound absent body accepted")
	}
	r, e = reclaimBackupPair(ctx, body, keys, trust, plan, false, clock, func(string) error { return nil })
	if e != nil || !r.Expired || r.Applied || r.BodyRemoved {
		t.Fatal(r, e)
	}
	r, e = reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(stage string) error {
		if stage == "pair:body_removed" {
			if _, e := os.Stat(filepath.Join(keys, "keys/master-000001.key")); e != nil {
				t.Fatal("keys removed before body", e)
			}
		}
		return nil
	})
	if e != nil || !r.Applied || !r.BodyRemoved || !r.KeysRemoved || r.RestoreReady {
		t.Fatal(r, e)
	}
	if _, e = ReclaimBackupPair(ctx, body, keys, trust, plan, true); e == nil {
		t.Fatal("retired plan reused")
	}
	stop := errors.New("injected interruption")
	stages := []string{"body:backup:reclaim_file", "pair:body_retired", "pair:body_removed", "keys:backup:reclaim_file", "pair:retired"}
	for i, p := range pairs {
		r, e = reclaimBackupPair(ctx, p[0], p[1], trust, p[2], true, clock, func(stage string) error {
			if stage == stages[i] {
				return stop
			}
			return nil
		})
		if !errors.Is(e, stop) || r.Applied {
			t.Fatal(stages[i], r, e)
		}
		if _, e = json.Marshal(r); e != nil {
			t.Fatal(e)
		}
		if i == 0 || i == 1 {
			if _, e = os.Stat(filepath.Join(p[1], "bundle.json")); e != nil {
				t.Fatal("keys lost on body failure", e)
			}
		}
		if i == 1 {
			if _, e = reclaimBackupPair(ctx, p[0], p[1], trust, p[2], true, clock, func(string) error { return nil }); e == nil {
				t.Fatal("retired body root automatically touched")
			}
			entries, e := os.ReadDir(p[0])
			if e != nil || len(entries) != 0 {
				t.Fatal(entries, e)
			}
			if e = os.Remove(p[0]); e != nil {
				t.Fatal(e)
			}
		}
		if i == 4 {
			if _, e = reclaimBackupPair(ctx, p[0], p[1], trust, p[2], true, clock, func(string) error { return nil }); e == nil {
				t.Fatal("retired key root reused")
			}
			entries, e := os.ReadDir(p[1])
			if e != nil || len(entries) != 0 {
				t.Fatal(entries, e)
			}
			continue
		}
		r, e = reclaimBackupPair(ctx, p[0], p[1], trust, p[2], true, clock, func(string) error { return nil })
		if e != nil || !r.Applied || !r.BodyRemoved || !r.KeysRemoved {
			t.Fatal(stages[i], r, e)
		}
	}
}

func TestBackupPairRejection(t *testing.T) {
	cfg, body := backupFixture(t)
	ctx := context.Background()
	parent := filepath.Dir(body)
	keys, trust, plan := filepath.Join(parent, "keys"), filepath.Join(parent, "trust.json"), filepath.Join(parent, "plan.json")
	if _, e := CaptureOfflineBackup(ctx, cfg, body); e != nil {
		t.Fatal(e)
	}
	if _, e := ExportBackupKeys(ctx, cfg, body, keys); e != nil {
		t.Fatal(e)
	}
	if _, e := ExportBackupTrust(ctx, cfg, trust); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	clock := func() time.Time { return now }
	if _, e := planBackupPairReclamation(ctx, cfg, body, keys, trust, plan, clock); e != nil {
		t.Fatal(e)
	}
	now = now.Add(25 * time.Hour)
	raw, e := os.ReadFile(plan)
	if e != nil {
		t.Fatal(e)
	}
	reject := func() {
		t.Helper()
		r, e := reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(string) error { return nil })
		if e == nil || r.Applied {
			t.Fatal(r, e)
		}
		if _, e = os.Stat(filepath.Join(body, "manifest.json")); e != nil {
			t.Fatal("rejection mutated body", e)
		}
	}
	var env backupPairEnvelope
	if e = json.Unmarshal(raw, &env); e != nil {
		t.Fatal(e)
	}
	env.Signature = "AAAAAAAA"
	bad, e := json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(plan, bad, 0600); e != nil {
		t.Fatal(e)
	}
	reject()
	if e = os.WriteFile(plan, raw, 0600); e != nil {
		t.Fatal(e)
	}
	trustRaw, e := os.ReadFile(trust)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(trust, append(trustRaw, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	reject()
	if e = os.WriteFile(trust, trustRaw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(keys, keys+"-old"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(keys, 0700); e != nil {
		t.Fatal(e)
	}
	reject()
	if e = os.Remove(keys); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(keys+"-old", keys); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(body, body+"-old"); e != nil {
		t.Fatal(e)
	}
	if _, e = reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(string) error { return nil }); e == nil {
		t.Fatal("body absent without retirement accepted")
	}
	if e = os.Rename(body+"-old", body); e != nil {
		t.Fatal(e)
	}
	manifest := filepath.Join(keys, "bundle.json")
	m, e := os.ReadFile(manifest)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(manifest, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	reject()
	if e = os.WriteFile(manifest, m, 0600); e != nil {
		t.Fatal(e)
	}
	now = now.Add(-26 * time.Hour)
	reject()
	now = now.Add(26 * time.Hour)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = ReclaimBackupPair(canceled, body, keys, trust, plan, true); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e = os.WriteFile(plan+backupKeysRetireSuffix, []byte("occupied"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(string) error { return nil })
	if e == nil || r.BodyRemoved || r.Applied {
		t.Fatal(r, e)
	}
	if _, e = os.Stat(filepath.Join(keys, "bundle.json")); e != nil {
		t.Fatal("keys removed on plan state failure", e)
	}
	if e = os.Remove(plan + backupKeysRetireSuffix); e != nil {
		t.Fatal(e)
	}
	r, e = reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(stage string) error {
		if stage == "pair:body_removed" {
			return os.Mkdir(body, 0700)
		}
		return nil
	})
	if e == nil || !r.BodyRemoved || r.Applied {
		t.Fatal(r, e)
	}
	if _, e = os.Stat(filepath.Join(keys, "bundle.json")); e != nil {
		t.Fatal("keys removed with replacement body", e)
	}
	if _, e = reclaimBackupPair(ctx, body, keys, trust, plan, true, clock, func(string) error { return nil }); e == nil {
		t.Fatal("replacement body root removed")
	}
}
