// 定期暗号化・破損検出・Docker停止後の再送を、Goの同じ入口と子process境界で検査する。
package sealedbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type syncFixture struct {
	root, name             string
	body                   []byte
	expires                int64
	logs                   []byte
	logErr, packErr        error
	packs, sends, cleanups int
	testing                *testing.T
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	s := &syncFixture{root: root, name: "backup-" + strings.Repeat("a", 32), body: []byte("complete ciphertext fixture"), expires: time.Now().Add(time.Hour).UnixNano(), testing: t}
	s.logs = []byte(fmt.Sprintf(`{"status":"completed","name":%q,"preparation":{"complete":true,"restore_ready":false,"capture":{"expires_at_ns":%q}}}`, s.name, strconv.FormatInt(s.expires, 10)))
	return s
}
func (s *syncFixture) runner(ctx context.Context, name string, args []string, in io.Reader, out, diagnostics io.Writer) error {
	s.testing.Helper()
	if name == "docker" && args[0] == "logs" {
		if s.logErr != nil {
			return s.logErr
		}
		_, e := out.Write(s.logs)
		return e
	}
	if name == "docker" && args[0] == "run" {
		s.packs++
		if !slices.Contains(args, "pack") || slices.Contains(args, "/bin/sh") || slices.Contains(args, "-c") {
			s.testing.Fatal("non-Go pack", args)
		}
		if s.packErr != nil {
			return s.packErr
		}
		_, e := out.Write(s.body)
		return e
	}
	if name == "docker" && args[0] == "rm" {
		s.cleanups++
		if len(args) != 3 || args[1] != "-f" || !strings.HasPrefix(args[2], "oimo-seal-helper-") || ctx.Err() != nil {
			s.testing.Fatal("invalid helper cleanup", args, ctx.Err())
		}
		return nil
	}
	if name == "ssh" {
		s.sends++
		if args[0] != "-oBatchMode=yes" || !strings.Contains(args[len(args)-1], "receive --root") {
			s.testing.Fatal(args)
		}
		raw, e := io.ReadAll(in)
		if e != nil {
			return e
		}
		m, e := LoadManifest(filepath.Join(s.root, s.name+".json"))
		if e != nil {
			return e
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != m.SHA256 {
			return errors.New("receiver hash mismatch")
		}
		return json.NewEncoder(out).Encode(acknowledgement(m, "installed"))
	}
	s.testing.Fatal(name, args)
	return errors.New("unexpected command")
}
func (s *syncFixture) sync(dest bool) error {
	o := SyncOptions{Container: "fixture", Image: "fixture:local", Source: s.root, Output: s.root, Runner: s.runner}
	if dest {
		o.Destination = "fixture:/backup"
	}
	return Sync(context.Background(), o, io.Discard)
}
func TestSyncCiphertextRepairAndLogIndependentSend(t *testing.T) {
	s := newSyncFixture(t)
	if e := s.sync(false); e != nil {
		t.Fatal(e)
	}
	if s.packs != 1 {
		t.Fatal(s.packs)
	}
	if e := s.sync(true); e != nil {
		t.Fatal(e)
	}
	if s.packs != 1 || s.sends != 1 {
		t.Fatal(s.packs, s.sends)
	}
	for _, bad := range [][]byte{bytes.Repeat([]byte("x"), len(s.body)), s.body[:len(s.body)-1]} {
		if e := os.WriteFile(filepath.Join(s.root, s.name+".seal"), bad, 0600); e != nil {
			t.Fatal(e)
		}
		if e := s.sync(true); e != nil {
			t.Fatal(e)
		}
	}
	if s.packs != 3 {
		t.Fatal("corruption not rebuilt", s.packs)
	}
	s.logs = nil
	if e := s.sync(true); e != nil {
		t.Fatal(e)
	}
	failure := errors.New("docker offline")
	s.logErr = failure
	before := s.sends
	if e := s.sync(true); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	if s.sends != before+1 {
		t.Fatal("existing copy not sent", s.sends, before)
	}
}
func TestSyncFailedRebuildAndMissingLog(t *testing.T) {
	s := newSyncFixture(t)
	s.sync(false)
	os.WriteFile(filepath.Join(s.root, s.name+".seal"), []byte("damaged"), 0600)
	s.packErr = errors.New("encryption error")
	if e := s.sync(true); e == nil {
		t.Fatal("failed encryption accepted")
	}
	if s.sends != 0 {
		t.Fatal("bad ciphertext sent")
	}
	if s.cleanups != 1 {
		t.Fatal("failed helper not removed", s.cleanups)
	}
	if _, e := os.Lstat(filepath.Join(s.root, s.name+".json")); !os.IsNotExist(e) {
		t.Fatal("invalid completion retained", e)
	}
	s.packErr = nil
	if e := s.sync(false); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(s.root, s.name+".seal"), []byte("bad"), 0600)
	s.logs = nil
	if e := s.sync(true); e == nil {
		t.Fatal("corrupt orphan sent")
	}
	if s.sends != 0 {
		t.Fatal(s.sends)
	}
}

func TestSyncEmptyCiphertextHasNoManifest(t *testing.T) {
	s := newSyncFixture(t)
	s.body = nil
	if e := s.sync(true); e == nil {
		t.Fatal("empty encryption accepted")
	}
	if _, e := os.Lstat(filepath.Join(s.root, s.name+".json")); !os.IsNotExist(e) {
		t.Fatal("empty completion installed", e)
	}
	if s.sends != 0 {
		t.Fatal("empty ciphertext sent")
	}
}
func TestSyncExpiryAndPartials(t *testing.T) {
	s := newSyncFixture(t)
	s.sync(false)
	m, e := LoadManifest(filepath.Join(s.root, s.name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	m.ExpiresAtNS = time.Now().Add(-time.Hour).UnixNano()
	raw, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(s.root, s.name+".json"), raw, 0600)
	s.logs = nil
	for _, suffix := range []string{".partial", ".json.partial"} {
		os.WriteFile(filepath.Join(s.root, s.name+suffix), []byte("unfinished"), 0600)
	}
	if e := s.sync(true); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(s.root)
	if len(entries) != 1 || entries[0].Name() != ".lock" {
		t.Fatal("expiry leftovers", entries)
	}
	if s.sends != 0 {
		t.Fatal("expired copy sent")
	}
}
func TestSendAcknowledgementStrictness(t *testing.T) {
	s := newSyncFixture(t)
	s.sync(false)
	for _, raw := range []string{`{}`, `[]`, `{"protocol":true}`, strings.Repeat("x", 8193)} {
		_, e := Send(context.Background(), filepath.Join(s.root, s.name+".seal"), filepath.Join(s.root, s.name+".json"), SendOptions{Destination: "fixture:/backup", Runner: func(_ context.Context, _ string, _ []string, _ io.Reader, out, diag io.Writer) error {
			_, e := io.WriteString(out, raw)
			return e
		}})
		if e == nil {
			t.Fatal("bad ACK accepted", raw[:min(len(raw), 50)])
		}
	}
}
