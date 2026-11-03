// 受信・再送・保存障害・期限回収を、実fileと注入した停止境界で確認する。
package sealedbackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func transferFixture(t *testing.T) (string, Header, []byte) {
	t.Helper()
	body := bytes.Repeat([]byte("sealed fixture"), 1024)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root, Header{Protocol: 1, Manifest: Manifest{Name: "backup-" + strings.Repeat("a", 32), SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), ExpiresAtNS: time.Now().Add(time.Hour).UnixNano(), RestoreReady: false}, Size: int64(len(body))}, body
}

func assertGeneration(t *testing.T, root string, h Header, body []byte) {
	t.Helper()
	dir := filepath.Join(root, h.Manifest.Generation())
	raw, err := os.ReadFile(filepath.Join(dir, "archive.seal"))
	if err != nil || !bytes.Equal(raw, body) {
		t.Fatal("archive", err)
	}
	m, err := LoadManifest(filepath.Join(dir, "manifest.json"))
	if err != nil || m != h.Manifest {
		t.Fatal("manifest", m, err)
	}
}

func TestReceiveResendAndPreviousGeneration(t *testing.T) {
	root, h, body := transferFixture(t)
	r := NewReceiver(root)
	ack, err := r.Receive(bytes.NewReader(body), h)
	if err != nil || ack.Status != "installed" {
		t.Fatal(ack, err)
	}
	before, _ := os.Stat(filepath.Join(root, h.Manifest.Generation()))
	r.openNew = func(string) (durableFile, error) { return nil, syscall.ENOSPC }
	ack, err = r.Receive(bytes.NewReader(body), h)
	if err != nil || ack.Status != "existing" {
		t.Fatal(ack, err)
	}
	after, _ := os.Stat(filepath.Join(root, h.Manifest.Generation()))
	if !os.SameFile(before, after) {
		t.Fatal("rewrote existing generation")
	}
	r = NewReceiver(root)
	other := h
	other.Manifest.Name = "backup-" + strings.Repeat("b", 32)
	for _, bad := range [][]byte{body[:12], append(bytes.Clone(body), 'x'), bytes.Repeat([]byte("x"), len(body))} {
		if _, err := r.Receive(bytes.NewReader(bad), other); err == nil {
			t.Fatal("bad stream accepted")
		}
		assertGeneration(t, root, h, body)
	}
	if _, err := r.Receive(bytes.NewReader(body), other); err != nil {
		t.Fatal(err)
	}
	assertGeneration(t, root, h, body)
	assertGeneration(t, root, other, body)
}

func TestReceiveMetadataStrict(t *testing.T) {
	_, h, _ := transferFixture(t)
	raw, _ := json.Marshal(h)
	for _, bad := range []string{`{}`, strings.Replace(string(raw), `"protocol":1`, `"protocol":true`, 1), strings.Replace(string(raw), `"protocol":1`, `"protocol":1,"protocol":1`, 1), strings.Replace(string(raw), `"restore_ready":false`, `"restore_ready":null`, 1), strings.Repeat("x", 8193)} {
		if _, err := ParseHeader([]byte(bad)); err == nil {
			t.Fatal("accepted", bad[:min(len(bad), 60)])
		}
	}
	for _, dest := range []string{"-F:/backup", "a:/x/../y", "a:/x/./y", "a://x", "a:/x$(id)", "a:relative"} {
		if _, _, err := ParseDestination(dest); err == nil {
			t.Fatal(dest)
		}
	}
}

func TestReceiveSyncRenameAndCloseFailures(t *testing.T) {
	for _, phase := range []string{"write", "short", "sync", "close", "manifest-write", "manifest-short", "manifest-sync", "manifest-close", "rename", "stage", "parent"} {
		t.Run(phase, func(t *testing.T) {
			root, h, body := transferFixture(t)
			r := NewReceiver(root)
			if _, err := r.Receive(bytes.NewReader(body), h); err != nil {
				t.Fatal(err)
			}
			other := h
			other.Manifest.Name = "backup-" + strings.Repeat("b", 32)
			injected := errors.New("injected " + phase)
			if phase == "rename" {
				r.rename = func(string, string) error { return injected }
			}
			if phase == "parent" || phase == "stage" {
				r.syncDir = func(path string) error {
					if phase == "parent" && path == root || phase == "stage" && path != root {
						return injected
					}
					return syncDirectory(path)
				}
			}
			if phase != "rename" && phase != "parent" && phase != "stage" {
				r.openNew = func(path string) (durableFile, error) {
					f, e := openNewFile(path)
					if e != nil {
						return nil, e
					}
					fault := phase
					if strings.HasPrefix(phase, "manifest-") {
						if filepath.Base(path) != "manifest.json" {
							return f, nil
						}
						fault = strings.TrimPrefix(phase, "manifest-")
					}
					return &receiveFault{File: f, phase: fault, err: injected}, nil
				}
			}
			if _, err := r.Receive(bytes.NewReader(body), other); err == nil {
				t.Fatal("failure acknowledged")
			}
			assertGeneration(t, root, h, body)
			if phase == "parent" {
				assertGeneration(t, root, other, body)
				if a, e := NewReceiver(root).Receive(bytes.NewReader(body), other); e != nil || a.Status != "existing" {
					t.Fatal(a, e)
				}
			} else if _, e := os.Lstat(filepath.Join(root, other.Manifest.Generation())); !os.IsNotExist(e) {
				t.Fatal("published failed generation", e)
			}
		})
	}
}

func TestReceiveExpiresBeforePublication(t *testing.T) {
	root, h, body := transferFixture(t)
	r := NewReceiver(root)
	calls := 0
	r.now = func() time.Time {
		calls++
		if calls == 1 {
			return time.Unix(0, h.Manifest.ExpiresAtNS-1)
		}
		return time.Unix(0, h.Manifest.ExpiresAtNS+1)
	}
	if _, e := r.Receive(bytes.NewReader(body), h); e == nil {
		t.Fatal("backup expired during receive was published")
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 1 || entries[0].Name() != ".receive.lock" {
		t.Fatal("expired receive retained", entries, e)
	}
}

type receiveFault struct {
	*os.File
	phase string
	err   error
}

func (f *receiveFault) Write(b []byte) (int, error) {
	if f.phase == "write" {
		return 0, f.err
	}
	if f.phase == "short" {
		return f.File.Write(b[:len(b)/2])
	}
	return f.File.Write(b)
}
func (f *receiveFault) Sync() error {
	if f.phase == "sync" {
		return f.err
	}
	return f.File.Sync()
}
func (f *receiveFault) Close() error {
	e := f.File.Close()
	if f.phase == "close" {
		return errors.Join(e, f.err)
	}
	return e
}

func TestSweepResumesWithoutManifest(t *testing.T) {
	root, h, body := transferFixture(t)
	r := NewReceiver(root)
	if _, e := r.Receive(bytes.NewReader(body), h); e != nil {
		t.Fatal(e)
	}
	h.Manifest.ExpiresAtNS = time.Now().Add(-time.Hour).UnixNano()
	b, _ := json.Marshal(h.Manifest)
	if e := os.WriteFile(filepath.Join(root, h.Manifest.Generation(), "manifest.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	injected := errors.New("stop reclamation")
	r.removePair = func(path string) error {
		if strings.HasPrefix(filepath.Base(path), ".expired-") {
			os.Remove(filepath.Join(path, "manifest.json"))
			return injected
		}
		return removePairDirectory(path)
	}
	if _, e := r.Sweep(); !errors.Is(e, injected) {
		t.Fatal(e)
	}
	n, e := NewReceiver(root).Sweep()
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if entry.Name() != ".receive.lock" {
			t.Fatal("leftover", entry.Name())
		}
	}
}

func TestReceiveExpiryAndCorruption(t *testing.T) {
	root, h, body := transferFixture(t)
	r := NewReceiver(root)
	r.now = func() time.Time { return time.Unix(0, h.Manifest.ExpiresAtNS+1) }
	if _, e := r.Receive(bytes.NewReader(body), h); e == nil {
		t.Fatal("expired input accepted")
	}
	r = NewReceiver(root)
	if _, e := r.Receive(bytes.NewReader(body), h); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, h.Manifest.Generation(), "archive.seal")
	bad := bytes.Repeat([]byte("x"), len(body))
	os.WriteFile(p, bad, 0600)
	if _, e := r.Receive(bytes.NewReader(body), h); e == nil {
		t.Fatal("corrupt existing accepted")
	}
	raw, _ := os.ReadFile(p)
	if !bytes.Equal(raw, bad) {
		t.Fatal("overwrote existing")
	}
}

var _ io.Writer = (*receiveFault)(nil)
