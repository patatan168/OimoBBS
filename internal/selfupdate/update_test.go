// 確認済みSHA・二重送信・有効期限・再起動後の状態とUnix socketの境界を検証する。
package selfupdate

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeWorker struct {
	latestRevision           string
	prepareError, applyError error
	prepareGate              <-chan struct{}
	prepares, applies        atomic.Int32
}

func (w *fakeWorker) latest(context.Context, string) (string, error) { return w.latestRevision, nil }
func (w *fakeWorker) prepare(ctx context.Context, _ State) error {
	w.prepares.Add(1)
	if w.prepareGate != nil {
		select {
		case <-w.prepareGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return w.prepareError
}
func (w *fakeWorker) apply(context.Context, State) error { w.applies.Add(1); return w.applyError }

func managerFixture(t *testing.T, w worker) *Manager {
	t.Helper()
	c := Config{StateDir: t.TempDir(), CurrentRevision: strings.Repeat("a", 40)}
	m, err := newManager(t.Context(), c, w)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func checked(t *testing.T, m *Manager) State {
	t.Helper()
	if _, err := m.Check(); err != nil {
		t.Fatal(err)
	}
	m.wg.Wait()
	return m.Snapshot()
}

func TestConfirmationAndReplay(t *testing.T) {
	gate := make(chan struct{})
	w := &fakeWorker{latestRevision: strings.Repeat("b", 40), prepareGate: gate}
	m := managerFixture(t, w)
	s := checked(t, m)
	if s.Phase != "ready" || len(s.Token) != 64 {
		t.Fatal(s)
	}
	for _, in := range [][2]string{{"", s.LatestRevision}, {s.Token, strings.Repeat("c", 40)}, {strings.Repeat("f", 64), s.LatestRevision}} {
		if _, err := m.Apply(in[0], in[1]); !errors.Is(err, ErrConflict) {
			t.Fatal("unconfirmed update", err)
		}
	}
	if _, err := m.Apply(s.Token, s.LatestRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(s.Token, s.LatestRevision); err != nil {
		t.Fatal("retry", err)
	}
	if _, err := m.Check(); !errors.Is(err, ErrConflict) {
		t.Fatal("parallel check", err)
	}
	close(gate)
	m.wg.Wait()
	if w.prepares.Load() != 1 || w.applies.Load() != 1 || m.Snapshot().CurrentRevision != s.LatestRevision || m.Snapshot().Phase != "complete" {
		t.Fatal(m.Snapshot())
	}
	if _, err := m.Apply(s.Token, s.LatestRevision); err != nil || w.applies.Load() != 1 {
		t.Fatal("completed replay", err)
	}
	loaded, err := newManager(t.Context(), m.config, w)
	if err != nil || loaded.Snapshot().CurrentRevision != s.LatestRevision || loaded.Snapshot().Phase != "complete" {
		t.Fatal("durable result", err)
	}
}

func TestExpiredAndReplacedConfirmation(t *testing.T) {
	w := &fakeWorker{latestRevision: strings.Repeat("b", 40)}
	m := managerFixture(t, w)
	s := checked(t, m)
	m.mu.Lock()
	m.state.Expires = time.Now().Add(-time.Second)
	m.mu.Unlock()
	if _, err := m.Apply(s.Token, s.LatestRevision); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	next := checked(t, m)
	if next.Token == s.Token {
		t.Fatal("confirmation token reused")
	}
	if _, err := m.Apply(s.Token, s.LatestRevision); !errors.Is(err, ErrConflict) {
		t.Fatal("stale form", err)
	}
	if w.prepares.Load() != 0 || w.applies.Load() != 0 {
		t.Fatal("expired form started an update")
	}
}

func TestFailuresDoNotAdvanceInstalledRevision(t *testing.T) {
	for _, stage := range []string{"prepare", "apply"} {
		t.Run(stage, func(t *testing.T) {
			w := &fakeWorker{latestRevision: strings.Repeat("b", 40)}
			if stage == "prepare" {
				w.prepareError = errors.New("failed")
			} else {
				w.applyError = errors.New("failed")
			}
			m := managerFixture(t, w)
			s := checked(t, m)
			if _, err := m.Apply(s.Token, s.LatestRevision); err != nil {
				t.Fatal(err)
			}
			m.wg.Wait()
			if got := m.Snapshot(); got.Phase != "failed" || got.CurrentRevision != strings.Repeat("a", 40) {
				t.Fatal(got)
			}
			if stage == "prepare" && w.applies.Load() != 0 {
				t.Fatal("deployment after prepare failure")
			}
			if _, err := m.Apply(s.Token, s.LatestRevision); !errors.Is(err, ErrConflict) {
				t.Fatal("failed update retried automatically")
			}
		})
	}
}

func TestInterruptedUpdateDoesNotRestart(t *testing.T) {
	w := &fakeWorker{}
	m := managerFixture(t, w)
	m.mu.Lock()
	m.state.Phase = "applying"
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := newManager(t.Context(), m.config, w)
	if err != nil || loaded.Snapshot().Phase != "failed" || w.applies.Load() != 0 {
		t.Fatal(err)
	}
}

func TestNoUpdateAndUnavailableStorage(t *testing.T) {
	w := &fakeWorker{latestRevision: strings.Repeat("a", 40)}
	m := managerFixture(t, w)
	if s := checked(t, m); s.Phase != "current" || s.Token != "" {
		t.Fatal(s)
	}
	m.config.StateDir = filepath.Join(m.config.StateDir, "missing")
	if _, err := m.Check(); err == nil || m.Snapshot().Phase != "current" {
		t.Fatal("failed persistence started a job")
	}
}

func TestCorruptStateDoesNotResetInstalledRevision(t *testing.T) {
	w := &fakeWorker{}
	m := managerFixture(t, w)
	for _, raw := range []string{`{}`, `{"phase":"ready"}`, `not json`} {
		if err := os.WriteFile(filepath.Join(m.config.StateDir, "state.json"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := newManager(t.Context(), m.config, w); err == nil {
			t.Fatal("corrupt state accepted", raw)
		}
	}
}

func TestUnixSocketProtocol(t *testing.T) {
	w := &fakeWorker{latestRevision: strings.Repeat("b", 40)}
	m := managerFixture(t, w)
	socket := filepath.Join(t.TempDir(), "control.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: m.handler()}
	go server.Serve(l)
	t.Cleanup(func() { server.Close(); m.wg.Wait() })
	client, err := NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := client.Request(t.Context(), "status", "", ""); err != nil || s.Phase != "idle" {
		t.Fatal(s, err)
	}
	if _, err := client.Request(t.Context(), "check", "", ""); err != nil {
		t.Fatal(err)
	}
	m.wg.Wait()
	s := m.Snapshot()
	if _, err := client.Request(t.Context(), "apply", "wrong", s.LatestRevision); err == nil {
		t.Fatal("invalid token accepted")
	}
	if _, err := client.Request(t.Context(), "apply", s.Token, s.LatestRevision); err != nil {
		t.Fatal(err)
	}
	m.wg.Wait()
	if m.Snapshot().Phase != "complete" {
		t.Fatal(m.Snapshot())
	}
	for _, tc := range []struct {
		method, path, body, origin, host string
		want                             int
	}{
		{"GET", "/check", "", "", "updater", 404},
		{"POST", "/check", `{}`, "https://evil.example", "updater", 403},
		{"POST", "/apply", `{"token":"x","revision":"-c"}`, "", "updater", 400},
		{"POST", "/check", `{"command":"bad"}`, "", "updater", 400},
		{"GET", "/status", "", "", "evil.example", 403},
	} {
		r := httptest.NewRequest(tc.method, "http://updater"+tc.path, strings.NewReader(tc.body))
		r.Host = tc.host
		r.Header.Set("Origin", tc.origin)
		response := httptest.NewRecorder()
		m.handler().ServeHTTP(response, r)
		if response.Code != tc.want {
			t.Fatal(tc, response.Code)
		}
	}
}

func TestArchiveRejectsUnsafeEntries(t *testing.T) {
	for _, header := range []*tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg},
		{Name: "/absolute", Typeflag: tar.TypeReg},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc"},
		{Name: "hard", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"},
		{Name: "large", Typeflag: tar.TypeReg, Size: 1<<30 + 1},
	} {
		var archive bytes.Buffer
		writer := tar.NewWriter(&archive)
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		if err := extractSource(&archive, t.TempDir()); err == nil {
			t.Fatal("unsafe entry", header)
		}
	}
}

func gitCommand(t *testing.T, directory string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = directory
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test", "GIT_COMMITTER_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid", "GIT_COMMITTER_EMAIL=test@example.invalid")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(args, err, string(raw))
	}
	return strings.TrimSpace(string(raw))
}

func TestGitFetchAndPinnedArchive(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git required")
	}
	repo := t.TempDir()
	gitCommand(t, repo, "init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(repo, "value"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	gitCommand(t, repo, "add", "value")
	gitCommand(t, repo, "commit", "-m", "first")
	current := gitCommand(t, repo, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repo, "value"), []byte("confirmed"), 0600); err != nil {
		t.Fatal(err)
	}
	gitCommand(t, repo, "commit", "-am", "second")
	latest := gitCommand(t, repo, "rev-parse", "HEAD")
	bare := filepath.Join(t.TempDir(), "upstream.git")
	gitCommand(t, repo, "clone", "--bare", repo, bare)
	gitCommand(t, repo, "--git-dir="+bare, "update-server-info")
	upstream := httptest.NewServer(http.FileServer(http.Dir(bare)))
	defer upstream.Close()
	state := t.TempDir()
	c := Config{StateDir: state, PrepareCommand: []string{"/bin/cp", "{source}/value", "{job}/prepared-value"}, ApplyCommand: []string{"/bin/true"}}
	w := gitWorker{config: c, remote: upstream.URL}
	got, err := w.latest(t.Context(), current)
	if err != nil || got != latest {
		t.Fatal("fetch", got, err)
	}
	if _, err := w.latest(t.Context(), strings.Repeat("f", 40)); err == nil {
		t.Fatal("unrelated installed revision")
	}
	gitCommand(t, repo, "--git-dir="+filepath.Join(state, "repository.git"), "update-ref", "refs/heads/update-main", current)
	s := State{Job: strings.Repeat("a", 24), LatestRevision: latest}
	if err := w.prepare(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(state, "jobs", s.Job, "prepared-value"))
	if err != nil || string(raw) != "confirmed" {
		t.Fatal("unpinned source", string(raw), err)
	}
	if info, err := os.Stat(filepath.Join(state, "jobs", s.Job, "update.log")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private logs", err)
	}
	if err := w.apply(t.Context(), s); err != nil {
		t.Fatal(err)
	}
}

func TestConfigOwnershipAndCommands(t *testing.T) {
	dir := t.TempDir()
	c := Config{Socket: filepath.Join(dir, "control.sock"), StateDir: dir, CurrentRevision: strings.Repeat("a", 40), PrepareCommand: []string{"/bin/true"}, ApplyCommand: []string{"/bin/true"}}
	path := filepath.Join(dir, "agent.json")
	write := func(mode os.FileMode) {
		t.Helper()
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(0600)
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	write(0644)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("public configuration accepted")
	}
	write(0600)
	linked := filepath.Join(dir, "linked.json")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(linked); err == nil {
		t.Fatal("configuration symlink accepted")
	}
	c.PrepareCommand = []string{"relative-command"}
	write(0600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("relative executable accepted")
	}
	c.PrepareCommand = []string{"/bin/true"}
	c.CurrentRevision = "main"
	write(0600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("mutable installed revision accepted")
	}
}

func TestServeLifecycleAndExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := Config{Socket: filepath.Join(dir, "control.sock"), StateDir: dir, CurrentRevision: strings.Repeat("a", 40), PrepareCommand: []string{"/bin/true"}, ApplyCommand: []string{"/bin/true"}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c) }()
	client, err := NewClient(c.Socket)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatal("agent startup failed", err)
		default:
		}
		if _, err := client.Request(t.Context(), "status", "", ""); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not listen")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := os.Stat(c.Socket); err != nil {
		t.Fatal(err)
	}
	if err := Serve(t.Context(), c); err == nil {
		t.Fatal("concurrent agent accepted")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := client.Request(t.Context(), "status", "", ""); err == nil {
		t.Fatal("socket remained active")
	}
}
