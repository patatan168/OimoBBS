// 任意指定の検証用OpenSSHで、Go送受信・切断・ACK消失・認証復号を実行する。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"oimobbs/internal/sealedbackup"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGoSSHIntegration(t *testing.T) {
	binary := os.Getenv("OIMO_TEST_SEAL_BINARY")
	if binary == "" {
		t.Skip("OIMO_TEST_SEAL_BINARY is required for isolated OpenSSH integration")
	}
	ssh, e := exec.LookPath("ssh")
	if e != nil {
		t.Fatal(e)
	}
	sshd := "/usr/sbin/sshd"
	if _, e := os.Stat(sshd); e != nil {
		t.Fatal(e)
	}
	// StrictModesで公開鍵の全親directoryを検査するため、共有/tmpを使わない。
	work, e := os.MkdirTemp(filepath.Dir(binary), "ssh-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(work)
	for _, key := range []string{"host", "client"} {
		cmd := exec.CommandContext(t.Context(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(work, key))
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(e, string(b))
		}
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	account, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	serverConfig := filepath.Join(work, "sshd_config")
	config := fmt.Sprintf("ListenAddress 127.0.0.1\nPort %d\nHostKey %s/host\nPidFile %s/sshd.pid\nAuthorizedKeysFile %s/client.pub\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes yes\nAllowUsers %s\n", port, work, work, work, account.Username)
	os.WriteFile(serverConfig, []byte(config), 0600)
	hostPub, e := os.ReadFile(filepath.Join(work, "host.pub"))
	if e != nil {
		t.Fatal(e)
	}
	fields := strings.Fields(string(hostPub))
	known := filepath.Join(work, "known_hosts")
	knownBytes := []byte(fmt.Sprintf("[127.0.0.1]:%d %s %s\n", port, fields[0], fields[1]))
	os.WriteFile(known, knownBytes, 0600)
	clientConfig := filepath.Join(work, "ssh_config")
	os.WriteFile(clientConfig, []byte(fmt.Sprintf("Host go-backup-fixture\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityFile %s/client\n IdentitiesOnly yes\n UserKnownHostsFile %s\n GlobalKnownHostsFile /dev/null\n BatchMode yes\n StrictHostKeyChecking yes\n", port, account.Username, work, known)), 0600)
	log, e := os.OpenFile(filepath.Join(work, "sshd.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	server := exec.Command(sshd, "-D", "-e", "-f", serverConfig)
	server.Stdout = log
	server.Stderr = log
	if e = server.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { server.Process.Signal(syscall.SIGTERM); server.Wait(); log.Close() }()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		e := exec.CommandContext(ctx, ssh, "-F", clientConfig, "go-backup-fixture", "true").Run()
		cancel()
		if e == nil {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		raw, _ := os.ReadFile(filepath.Join(work, "sshd.log"))
		t.Fatal("sshd unavailable", string(raw))
	}
	root := filepath.Join(work, "receiver")
	os.Mkdir(root, 0700)
	private, public, e := sealedbackup.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	plain := bytes.Repeat([]byte("Go SSH authenticated fixture\n"), 80000)
	var encrypted bytes.Buffer
	if e := sealedbackup.Seal(&encrypted, bytes.NewReader(plain), public); e != nil {
		t.Fatal(e)
	}
	body := encrypted.Bytes()
	target := filepath.Join(work, "input.seal")
	os.WriteFile(target, body, 0600)
	h := sealedbackup.Header{Protocol: 1, Manifest: sealedbackup.Manifest{Name: "backup-" + strings.Repeat("a", 32), SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), ExpiresAtNS: time.Now().Add(time.Hour).UnixNano()}, Size: int64(len(body))}
	manifest := filepath.Join(work, "manifest.json")
	writeManifest := func() {
		raw, _ := json.Marshal(h.Manifest)
		if e := os.WriteFile(manifest, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeManifest()
	options := sealedbackup.SendOptions{Destination: "go-backup-fixture:" + root, Receiver: binary, SSHConfig: clientConfig}
	ack, e := sealedbackup.Send(t.Context(), target, manifest, options)
	if e != nil || ack.Status != "installed" {
		t.Fatal(ack, e)
	}
	previous := filepath.Join(root, h.Manifest.Generation())
	before, _ := os.Stat(previous)
	ack, e = sealedbackup.Send(t.Context(), target, manifest, options)
	after, _ := os.Stat(previous)
	if e != nil || ack.Status != "existing" || !os.SameFile(before, after) {
		t.Fatal(ack, e)
	}
	t.Log("Go SSH install and resend: installed -> existing; previous inode preserved")
	h.Manifest.Name = "backup-" + strings.Repeat("b", 32)
	for attempt := 0; attempt < 3; attempt++ {
		args, e := sealedbackup.SSHArguments(options.Destination, binary, h)
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.CommandContext(t.Context(), ssh, append([]string{"-F", clientConfig}, args...)...)
		pipe, e := cmd.StdinPipe()
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stdout = io.Discard
		var diag bytes.Buffer
		cmd.Stderr = &diag
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		if _, e = pipe.Write(body[:576<<10]); e != nil {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal(e)
		}
		seen := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			files, _ := filepath.Glob(filepath.Join(root, ".incoming-*", "archive.seal"))
			for _, p := range files {
				info, e := os.Stat(p)
				if e == nil && info.Size() >= 256<<10 {
					seen = true
				}
			}
			if seen {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cmd.Process.Kill()
		cmd.Wait()
		pipe.Close()
		if !seen {
			t.Fatal("no receiver progress", diag.String())
		}
		waitReceiver(t, root)
		if _, e := os.Lstat(filepath.Join(root, h.Manifest.Generation())); !os.IsNotExist(e) {
			t.Fatal("disconnected upload published", e)
		}
		old, e := os.ReadFile(filepath.Join(previous, "archive.seal"))
		if e != nil || !bytes.Equal(old, body) {
			t.Fatal("old copy changed", e)
		}
		t.Logf("Go SSH disconnection %d: previous copy unchanged", attempt+1)
	}
	writeManifest()
	ack, e = sealedbackup.Send(t.Context(), target, manifest, options)
	if e != nil || ack.Status != "installed" {
		t.Fatal(ack, e)
	}
	h.Manifest.Name = "backup-" + strings.Repeat("c", 32)
	writeManifest()
	lost := options
	lost.Runner = func(ctx context.Context, name string, args []string, in io.Reader, out, diag io.Writer) error {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = in
		cmd.Stdout = io.Discard
		cmd.Stderr = diag
		if e := cmd.Run(); e != nil {
			return e
		}
		return errors.New("simulated ACK loss")
	}
	if _, e := sealedbackup.Send(t.Context(), target, manifest, lost); e == nil {
		t.Fatal("missing acknowledgement accepted")
	}
	complete := filepath.Join(root, h.Manifest.Generation())
	first, _ := os.Stat(complete)
	ack, e = sealedbackup.Send(t.Context(), target, manifest, options)
	second, _ := os.Stat(complete)
	if e != nil || ack.Status != "existing" || !os.SameFile(first, second) {
		t.Fatal(ack, e)
	}
	t.Log("Go SSH ACK loss: existing generation reused")
	h.Manifest.Name = "backup-" + strings.Repeat("d", 32)
	writeManifest()
	bad := bytes.Clone(body)
	bad[len(bad)-1] ^= 1
	os.WriteFile(target, bad, 0600)
	if _, e := sealedbackup.Send(t.Context(), target, manifest, options); e == nil {
		t.Fatal("corrupt stream accepted")
	}
	os.WriteFile(target, body, 0600)
	os.WriteFile(known, nil, 0600)
	if _, e := sealedbackup.Send(t.Context(), target, manifest, options); e == nil {
		t.Fatal("unknown host key accepted")
	}
	os.WriteFile(known, knownBytes, 0600)
	t.Log("Go SSH modified stream and unknown host key: rejected")
	input, e := os.ReadFile(filepath.Join(previous, "archive.seal"))
	if e != nil {
		t.Fatal(e)
	}
	var opened bytes.Buffer
	if e := sealedbackup.Open(&opened, bytes.NewReader(input), private); e != nil || !bytes.Equal(opened.Bytes(), plain) {
		t.Fatal("received plaintext differs", e)
	}
	t.Logf("Go SSH received archive: %d plaintext bytes match", len(plain))
}
func waitReceiver(t *testing.T, root string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		_, e := sealedbackup.NewReceiver(root).Sweep()
		if e == nil {
			return
		}
		if !errors.Is(e, syscall.EWOULDBLOCK) {
			t.Fatal(e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("receiver lock retained")
}
