// Go CLIの受信と、受信processを実SIGKILLした後の再開を確認する。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/sealedbackup"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func receiveCLIData(t *testing.T) (string, sealedbackup.Header, []byte) {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	body := bytes.Repeat([]byte("ciphertext fixture\n"), 256000)
	h := sealedbackup.Header{Protocol: 1, Manifest: sealedbackup.Manifest{Name: "backup-" + strings.Repeat("a", 32), SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), ExpiresAtNS: time.Now().Add(time.Hour).UnixNano()}, Size: int64(len(body))}
	return root, h, body
}
func TestReceiveGoCLI(t *testing.T) {
	root, h, body := receiveCLIData(t)
	raw, _ := json.Marshal(h)
	var out bytes.Buffer
	args := []string{"receive", "--root", root, "--header", string(raw)}
	if e := runContext(t.Context(), args, bytes.NewReader(body), &out); e != nil {
		t.Fatal(e)
	}
	var ack sealedbackup.Acknowledgement
	if e := json.Unmarshal(out.Bytes(), &ack); e != nil || ack.Status != "installed" {
		t.Fatal(out.String(), e)
	}
	out.Reset()
	if e := runContext(t.Context(), args, bytes.NewReader(body), &out); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), `"existing"`) {
		t.Fatal(out.String())
	}
	out.Reset()
	if e := runContext(t.Context(), []string{"sweep", "--root", root}, bytes.NewReader(nil), &out); e != nil || !strings.Contains(out.String(), `"expired_generations_removed":0`) {
		t.Fatal(out.String(), e)
	}
}
func TestReceiveKilledProcess(t *testing.T) {
	if root := os.Getenv("OIMO_GO_RECEIVE_ROOT"); root != "" {
		if e := runContext(context.Background(), []string{"receive", "--root", root, "--header", os.Getenv("OIMO_GO_RECEIVE_HEADER")}, os.Stdin, os.Stdout); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
		os.Exit(0)
	}
	root, h, body := receiveCLIData(t)
	r := sealedbackup.NewReceiver(root)
	if _, e := r.Receive(bytes.NewReader(body), h); e != nil {
		t.Fatal(e)
	}
	previous := filepath.Join(root, h.Manifest.Generation(), "archive.seal")
	h.Manifest.Name = "backup-" + strings.Repeat("b", 32)
	raw, _ := json.Marshal(h)
	for attempt := 0; attempt < 3; attempt++ {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestReceiveKilledProcess$")
		cmd.Env = append(os.Environ(), "OIMO_GO_RECEIVE_ROOT="+root, "OIMO_GO_RECEIVE_HEADER="+string(raw))
		pipe, e := cmd.StdinPipe()
		if e != nil {
			t.Fatal(e)
		}
		var diag bytes.Buffer
		cmd.Stderr = &diag
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		if _, e = pipe.Write(body[:576<<10]); e != nil {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal(e, diag.String())
		}
		deadline := time.Now().Add(5 * time.Second)
		seen := false
		for time.Now().Before(deadline) {
			paths, _ := filepath.Glob(filepath.Join(root, ".incoming-*", "archive.seal"))
			for _, path := range paths {
				info, e := os.Stat(path)
				if e == nil && info.Size() >= 256<<10 {
					seen = true
				}
			}
			if seen {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !seen {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("receiver progress missing", diag.String())
		}
		if _, e := r.Sweep(); !errors.Is(e, syscall.EWOULDBLOCK) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("active receive was not locked", e)
		}
		cmd.Process.Kill()
		e = cmd.Wait()
		pipe.Close()
		var exited *exec.ExitError
		if !errors.As(e, &exited) || exited.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatal(e)
		}
		if _, e := os.Lstat(filepath.Join(root, h.Manifest.Generation())); !os.IsNotExist(e) {
			t.Fatal("partial generation published", e)
		}
		old, e := os.ReadFile(previous)
		if e != nil || !bytes.Equal(old, body) {
			t.Fatal("previous copy changed", e)
		}
	}
	ack, e := r.Receive(bytes.NewReader(body), h)
	if e != nil || ack.Status != "installed" {
		t.Fatal(ack, e)
	}
	pending, _ := filepath.Glob(filepath.Join(root, ".incoming-*"))
	if len(pending) != 0 {
		t.Fatal("stale incoming retained", pending)
	}
}
