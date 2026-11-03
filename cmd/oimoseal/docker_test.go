// 任意指定の隔離Dockerで、Pythonなしの署名検証・tar暗号化・再読込みを確認する。
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"oimobbs/internal/sealedbackup"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestGoDockerFixture は検証コンテナ内だけで使う準備・所有者復元の補助入口。
func TestGoDockerFixture(t *testing.T) {
	role := os.Getenv("OIMO_GO_DOCKER_ROLE")
	if role == "" {
		t.Skip("Docker fixture helper only")
	}
	root := "/fixture"
	if role == "owner" {
		uid, e := strconv.Atoi(os.Getenv("OIMO_GO_UID"))
		if e != nil {
			t.Fatal(e)
		}
		gid, e := strconv.Atoi(os.Getenv("OIMO_GO_GID"))
		if e != nil {
			t.Fatal(e)
		}
		if e := filepath.WalkDir(root, func(path string, entry fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			return os.Chown(path, uid, gid)
		}); e != nil {
			t.Fatal(e)
		}
		return
	}
	if _, e := exec.LookPath("python3"); e == nil {
		t.Fatal("fixture image unexpectedly includes Python")
	}
	name := "backup-" + strings.Repeat("a", 32)
	for _, dir := range []string{"copies", "keys", "pairs", "work", "encryption"} {
		if e := os.MkdirAll(filepath.Join(root, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	config := map[string]any{"schema_version": 1, "edge": nil, "maintenance": nil, "auto_reports": nil, "data_dir": filepath.Join(root, "site"), "public": map[string]any{"listen": "127.0.0.1:9080", "base_url": "http://127.0.0.1:9080", "tls_cert_file": "", "tls_key_file": ""}, "admin": map[string]any{"listen": "127.0.0.1:9081", "origin": "http://127.0.0.1:9081", "transport": "loopback_tunnel"}, "trusted_proxies": []string{}, "egress_budget_bits_per_second": 80000000}
	raw, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	configPath := filepath.Join(root, "config.json")
	if e := os.WriteFile(configPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	command := func(args ...string) []byte {
		cmd := exec.Command("oimobbs", args...)
		var diag bytes.Buffer
		cmd.Stderr = &diag
		out, e := cmd.Output()
		if e != nil {
			t.Fatal(args, e, diag.String())
		}
		return out
	}
	command("init", "--config", configPath, "--name", "Go backup fixture")
	result := command("backup", "prepare", "--config", configPath, "--output", filepath.Join(root, "copies", name), "--keys-output", filepath.Join(root, "keys", name), "--work-parent", filepath.Join(root, "work"))
	var complete struct {
		Complete bool `json:"complete"`
	}
	if e := json.Unmarshal(result, &complete); e != nil || !complete.Complete {
		t.Fatal("preparation incomplete", string(result), e)
	}
	if e := os.WriteFile(filepath.Join(root, "pairs", name+".json"), result, 0600); e != nil {
		t.Fatal(e)
	}
	private, public, e := sealedbackup.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "encryption", "public.key"), public, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "identity.private"), private, 0600); e != nil {
		t.Fatal(e)
	}
	wrapper := struct {
		Status      string          `json:"status"`
		Name        string          `json:"name"`
		Preparation json.RawMessage `json:"preparation"`
	}{"completed", name, json.RawMessage(result)}
	if e := json.NewEncoder(os.Stdout).Encode(wrapper); e != nil {
		t.Fatal(e)
	}
}

func TestGoDockerSyncIntegration(t *testing.T) {
	image := os.Getenv("OIMO_TEST_SEAL_IMAGE")
	fixture := os.Getenv("OIMO_TEST_SEAL_FIXTURE")
	if image == "" || fixture == "" {
		t.Skip("OIMO_TEST_SEAL_IMAGE and OIMO_TEST_SEAL_FIXTURE required")
	}
	work := t.TempDir()
	os.Chmod(work, 0700)
	source := filepath.Join(work, "source")
	os.Mkdir(source, 0700)
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "docker", args...)
		var diag bytes.Buffer
		cmd.Stderr = &diag
		out, e := cmd.Output()
		if e != nil {
			t.Fatal(args, e, diag.String())
		}
		return out
	}
	owner := func(uid, gid int) {
		run("run", "--rm", "--user", "0:0", "--network", "none", "-e", "OIMO_GO_DOCKER_ROLE=owner", "-e", fmt.Sprintf("OIMO_GO_UID=%d", uid), "-e", fmt.Sprintf("OIMO_GO_GID=%d", gid), "-v", source+":/fixture", "-v", fixture+":/fixture.test:ro", "--entrypoint", "/fixture.test", image, "-test.run=^TestGoDockerFixture$")
	}
	owner(10001, 10001)
	defer owner(os.Getuid(), os.Getgid())
	container := fmt.Sprintf("oimo-go-backup-fixture-%d-%d", os.Getpid(), time.Now().UnixNano())
	defer func() { exec.Command("docker", "rm", "-f", container).Run() }()
	run("run", "--name", container, "--network", "none", "-e", "OIMO_GO_DOCKER_ROLE=prepare", "-v", source+":/fixture", "-v", fixture+":/fixture.test:ro", "--entrypoint", "/fixture.test", image, "-test.run=^TestGoDockerFixture$")
	output := filepath.Join(work, "encrypted")
	var report bytes.Buffer
	options := sealedbackup.SyncOptions{Container: container, Image: image, Source: source, Output: output}
	if e := sealedbackup.Sync(t.Context(), options, &report); e != nil {
		t.Fatal(e, report.String())
	}
	name := "backup-" + strings.Repeat("a", 32)
	m, e := sealedbackup.LoadManifest(filepath.Join(output, name+".json"))
	if e != nil {
		t.Fatal(e)
	}

	owner(os.Getuid(), os.Getgid())
	prepRaw, e := os.ReadFile(filepath.Join(source, "pairs", name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	var prep struct {
		RestoreReady bool `json:"restore_ready"`
	}
	if e := json.Unmarshal(prepRaw, &prep); e != nil || m.RestoreReady != prep.RestoreReady {
		t.Fatal("restore readiness changed", m.RestoreReady, prep.RestoreReady, e)
	}
	private, e := os.ReadFile(filepath.Join(source, "identity.private"))
	if e != nil {
		t.Fatal(e)
	}
	encrypted, e := os.Open(filepath.Join(output, name+".seal"))
	if e != nil {
		t.Fatal(e)
	}
	var plain bytes.Buffer
	e = sealedbackup.Open(&plain, encrypted, private)
	encrypted.Close()
	if e != nil {
		t.Fatal(e)
	}
	restored := filepath.Join(work, "restored")
	os.Mkdir(restored, 0700)
	archive := tar.NewReader(&plain)
	files := 0
	for {
		header, e := archive.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		rel := filepath.FromSlash(header.Name)
		if filepath.IsAbs(rel) || strings.HasPrefix(filepath.Clean(rel), "..") {
			t.Fatal("unsafe fixture tar", rel)
		}
		path := filepath.Join(restored, rel)
		if header.Typeflag == tar.TypeDir {
			os.MkdirAll(path, 0700)
			continue
		}
		if header.Typeflag != tar.TypeReg {
			t.Fatal(header.Typeflag)
		}
		os.MkdirAll(filepath.Dir(path), 0700)
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		_, e = io.Copy(f, archive)
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			t.Fatal(e, closeErr)
		}
		files++
	}
	if files < 3 {
		t.Fatal("tar missing members", files)
	}
	run("run", "--rm", "--network", "none", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-v", restored+":/restored:ro", "--entrypoint", "oimobbs", image, "backup", "verify-with-keys", "--input", "/restored/copies/"+name, "--keys", "/restored/keys/"+name)
	t.Logf("Go Docker sync: no Python; %d archived files; decrypted signed copy and keys verified", files)
	// 空きがなくても既存出力を再利用する経路と同じく、正常コピーの再暗号化は起こさない。
	report.Reset()
	if e := sealedbackup.Sync(context.Background(), options, &report); e != nil {
		t.Fatal(e)
	}
	if report.Len() != 0 {
		t.Fatal("unnecessary re-encryption", report.String())
	}
}
