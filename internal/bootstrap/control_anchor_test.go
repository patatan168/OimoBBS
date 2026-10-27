// 認証済み境界の永続化・取り違え拒否・世代配置の読み取り専用判定を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestControlAnchorBindingAndLegacy(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	importCandidateAudit(t, r)
	key, err := controlAnchorKey(r.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key[:])
	dirs := []string{filepath.Join(candidateParent(t), "one"), filepath.Join(candidateParent(t), "two")}
	for _, dir := range dirs {
		if _, err = r.PrepareControlSnapshot(ctx, dir, 6); err != nil {
			t.Fatal(err)
		}
	}
	m, err := readCandidateManifest(dirs[0])
	if err != nil || m.Schema != 2 {
		t.Fatal(m.Schema, err)
	}
	item := m.Owners[0]
	path := filepath.Join(dirs[0], anchorFile(item))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := readControlAnchor(path, m.Site, m.ID, key)
	if err != nil || !reflect.DeepEqual(a.Owner, item) {
		t.Fatal(err)
	}
	wrongKey := key
	wrongKey[0] ^= 1
	for _, v := range []struct {
		site, id domain.ID
		key      domain.Hash
	}{{domain.NewID(), m.ID, key}, {m.Site, domain.NewID(), key}, {m.Site, m.ID, wrongKey}} {
		if _, err = readControlAnchor(path, v.site, v.id, v.key); err == nil {
			t.Fatal("wrong binding accepted")
		}
	}
	var env anchorEnvelope
	if err = json.Unmarshal(original, &env); err != nil {
		t.Fatal(err)
	}
	a.Owner.Proof.SourceHash[0] ^= 1
	env.Payload, _ = json.Marshal(a)
	forged, _ := json.Marshal(env)
	if err = os.WriteFile(path, forged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.VerifyControlSnapshot(ctx, dirs[0]); err == nil {
		t.Fatal("forged proof accepted")
	}
	if _, err = readControlAnchor(path, m.Site, m.ID, key); err == nil {
		t.Fatal("MAC verification bypassed")
	}
	other, err := os.ReadFile(filepath.Join(dirs[1], anchorFile(item)))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, other, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.VerifyControlSnapshot(ctx, dirs[0]); err == nil {
		t.Fatal("different candidate anchor accepted")
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.VerifyControlSnapshot(ctx, dirs[0]); err != nil {
		t.Fatal(err)
	}
	// 旧schemaは認証anchorの有無にかかわらず拒否する。
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = r.VerifyControlSnapshot(ctx, dirs[0]); err == nil {
		t.Fatal("missing anchor accepted")
	}
	m.Schema = 1
	raw, _ := json.Marshal(m)
	if err = os.WriteFile(filepath.Join(dirs[0], "candidate.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.VerifyControlSnapshot(ctx, dirs[0]); err == nil {
		t.Fatal("old candidate accepted")
	}
}

func TestControlGenerationInspection(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	importCandidateAudit(t, r)
	candidate := filepath.Join(candidateParent(t), "candidate")
	if _, err := r.PrepareControlSnapshot(ctx, candidate, 6); err != nil {
		t.Fatal(err)
	}
	m, err := readCandidateManifest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	item := m.Owners[0]
	key, err := controlAnchorKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key[:])
	dir := candidateParent(t)
	for _, name := range []string{"control.current", "control-000001.wal"} {
		raw, err := os.ReadFile(filepath.Join(cfg.DataDir, "site", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	inspect := func() (controlGeneration, error) { return inspectControlGeneration(dir, "site", m.Site, m.Site, key) }
	initial, err := inspect()
	if err != nil || initial.Anchor != nil {
		t.Fatal(err)
	}
	anchorName := fmt.Sprintf("control-%06d.anchor.json", item.Generation)
	anchorRaw, err := os.ReadFile(filepath.Join(candidate, anchorFile(item)))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeNew(filepath.Join(dir, anchorName), anchorRaw); err != nil {
		t.Fatal(err)
	}
	pending, err := inspect()
	if err != nil || len(pending.Pending) != 1 || pending.Pending[0] != anchorName {
		t.Fatal("pending anchor", pending.Pending, err)
	}
	log, err := store.OpenControlWithValidators(dir, 1, m.Site, 0, validateSiteValue, snapshotSiteValue)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(candidate, item.File))
	if err != nil {
		log.Close()
		t.Fatal(err)
	}
	result := log.SwitchSnapshot(raw)
	log.Close()
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	currentBefore, err := os.ReadFile(filepath.Join(dir, "control.current"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := inspect()
	if err != nil || got.Anchor == nil || got.Anchor.Candidate != m.ID || !reflect.DeepEqual(got.State, r.site.State()) || len(got.Retained) != 1 {
		t.Fatal(got.Retained, err)
	}
	for _, test := range []struct {
		name  string
		valid bool
	}{{"control-000003.wal", true}, {".install-123456", true}, {"control-000004.wal", false}, {"control-02.snap", false}, {"unknown", false}} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name)
			if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(path)
			result, err := inspect()
			if (err == nil) != test.valid {
				t.Fatal(err)
			}
			if test.valid && (len(result.Pending) != 1 || result.Pending[0] != test.name) {
				t.Fatal(result.Pending)
			}
		})
	}
	snapPath := filepath.Join(dir, fmt.Sprintf("control-%06d.snap", item.Generation))
	damaged := append([]byte{}, raw...)
	damaged[len(damaged)-1] ^= 1
	if err = os.WriteFile(snapPath, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = inspect(); err == nil {
		t.Fatal("corrupt active snapshot accepted")
	}
	if err = os.WriteFile(snapPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(dir, anchorName), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = inspect(); err == nil {
		t.Fatal("public anchor permissions accepted")
	}
	if err = os.Chmod(filepath.Join(dir, anchorName), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(dir, anchorName)); err != nil {
		t.Fatal(err)
	}
	if _, err = inspect(); err == nil {
		t.Fatal("active anchor missing")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "control.current"))
	if !reflect.DeepEqual(currentBefore, after) {
		t.Fatal("inspection changed current")
	}
}
