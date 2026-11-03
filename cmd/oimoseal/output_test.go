// 復号完了前の出力名を公開せず、保存失敗・同名競合・強制終了後も再実行できることを検査する。
package main

import (
	"bytes"
	"errors"
	"io"
	"oimobbs/internal/sealedbackup"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSealedOutputHiddenUntilComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restored.tar")
	injected := errors.New("injected authentication failure")
	err := newFile(path, func(w io.Writer) error {
		if _, err := w.Write([]byte("authenticated prefix")); err != nil {
			return err
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("incomplete output visible", err)
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed output retained", err)
	}
	if err := newFile(path, func(w io.Writer) error { _, err := w.Write([]byte("complete")); return err }); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "complete" {
		t.Fatal(string(raw), err)
	}
}

type faultyOutput struct {
	*os.File
	writeErr, syncErr, closeErr error
	short                       bool
	closes                      int
}

func (f *faultyOutput) Write(raw []byte) (int, error) {
	if f.writeErr != nil {
		n, err := f.File.Write(raw[:len(raw)/2])
		return n, errors.Join(err, f.writeErr)
	}
	if f.short {
		return f.File.Write(raw[:len(raw)/2])
	}
	return f.File.Write(raw)
}

func (f *faultyOutput) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *faultyOutput) Close() error {
	f.closes++
	return errors.Join(f.File.Close(), f.closeErr)
}

func TestSealedOutputStorageFailures(t *testing.T) {
	_, public, err := sealedbackup.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeErr, syncErr, closeErr := errors.New("write EIO"), errors.New("sync EIO"), errors.New("close EIO")
	for _, phase := range []string{"write", "short", "sync", "close", "write-close"} {
		t.Run(phase, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "sealed")
			var file *faultyOutput
			create := func(parent string) (outputFile, error) {
				raw, err := os.CreateTemp(parent, ".oimoseal-*.partial")
				if err != nil {
					return nil, err
				}
				file = &faultyOutput{File: raw}
				switch phase {
				case "write":
					file.writeErr = writeErr
				case "short":
					file.short = true
				case "sync":
					file.syncErr = syncErr
				case "close":
					file.closeErr = closeErr
				case "write-close":
					file.writeErr, file.closeErr = writeErr, closeErr
				}
				return file, nil
			}
			transform := func(w io.Writer) error { return sealedbackup.Seal(w, bytes.NewReader([]byte("fixture body")), public) }
			err := installNewFile(path, transform, create, func(string) error { t.Error("directory synced before complete output"); return nil })
			if err == nil || file.closes != 1 {
				t.Fatal("storage error or Close hidden", err, file.closes)
			}
			if phase == "write-close" && (!errors.Is(err, writeErr) || !errors.Is(err, closeErr)) {
				t.Fatal("compound error lost", err)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("failed output published", err)
			}
			partials, err := filepath.Glob(filepath.Join(parent, ".oimoseal-*.partial"))
			if err != nil || len(partials) != 0 {
				t.Fatal("partial output retained", partials, err)
			}
		})
	}
}

func TestSealedOutputDirectoryFailureKeepsCompleteFile(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "restored")
	injected := errors.New("directory EIO")
	err := installNewFile(path, func(w io.Writer) error { _, err := w.Write([]byte("complete")); return err },
		func(parent string) (outputFile, error) { return os.CreateTemp(parent, ".oimoseal-*.partial") },
		func(directory string) error {
			if directory != parent {
				t.Fatal(directory)
			}
			return injected
		})
	if !errors.Is(err, injected) {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "complete" {
		t.Fatal(string(raw), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("unsafe completed file", info, err)
	}
	if err := newFile(path, func(io.Writer) error { t.Fatal("existing output rewritten"); return nil }); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
}

func TestSealedOutputDoesNotReplaceConcurrentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restored.tar")
	err := newFile(path, func(w io.Writer) error {
		if _, err := w.Write([]byte("candidate")); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("other completed output"), 0600)
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatal("concurrent output replaced", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "other completed output" {
		t.Fatal(string(raw), err)
	}
}

func TestSealedOutputKilledProcess(t *testing.T) {
	if path := os.Getenv("OIMO_TEST_SEALED_OUTPUT"); path != "" {
		_ = newFile(path, func(w io.Writer) error {
			if _, err := w.Write(bytes.Repeat([]byte("private prefix\n"), 5000)); err != nil {
				return err
			}
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		})
		os.Exit(3)
	}
	path := filepath.Join(t.TempDir(), "restored.tar")
	command := exec.Command(os.Args[0], "-test.run=^TestSealedOutputKilledProcess$")
	command.Env = append(os.Environ(), "OIMO_TEST_SEALED_OUTPUT="+path)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal("child not killed", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("killed process published partial output", err)
	}
	partials, err := filepath.Glob(filepath.Join(filepath.Dir(path), outputPrefix(path)+"*.partial"))
	if err != nil || len(partials) != 1 {
		t.Fatal("expected private recovery temporary", partials, err)
	}
	if err := newFile(path, func(w io.Writer) error { _, err := w.Write([]byte("complete retry")); return err }); err != nil {
		t.Fatal("retry failed", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "complete retry" {
		t.Fatal(string(raw), err)
	}
	if _, err := os.Lstat(partials[0]); !os.IsNotExist(err) {
		t.Fatal("old partial retained after retry", err)
	}
}

func TestSealedOutputLocksOnlySameName(t *testing.T) {
	parent := t.TempDir()
	first, second := filepath.Join(parent, "first"), filepath.Join(parent, "second")
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- newFile(first, func(w io.Writer) error {
			_, err := w.Write([]byte("first complete output"))
			close(started)
			<-release
			return err
		})
	}()
	<-started
	defer func() {
		close(release)
		if err := <-finished; err != nil {
			t.Error(err)
		}
	}()
	if err := newFile(first, func(io.Writer) error { t.Error("same-name writer started"); return nil }); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal("same-name lock failed", err)
	}
	if err := newFile(second, func(w io.Writer) error { _, err := w.Write([]byte("second complete output")); return err }); err != nil {
		t.Fatal("other output blocked", err)
	}
	partials, err := filepath.Glob(filepath.Join(parent, outputPrefix(first)+"*.partial"))
	if err != nil || len(partials) != 1 {
		t.Fatal("active temporary removed", partials, err)
	}
}

func TestSealedOutputCleansLinkedTemporaryAfterInstall(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "complete")
	if err := os.WriteFile(path, []byte("complete output"), 0600); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(parent, outputPrefix(path)+"interrupted.partial")
	if err := os.Link(path, partial); err != nil {
		t.Fatal(err)
	}
	if err := newFile(path, func(io.Writer) error { t.Error("completed output rewritten"); return nil }); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("temporary alias retained", info, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "complete output" {
		t.Fatal(string(raw), err)
	}
}

func TestSealedOutputRejectsUnexpectedRecoveryFiles(t *testing.T) {
	for _, kind := range []string{"lock-symlink", "lock-hardlink", "partial-directory", "partial-symlink"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "output")
			other := filepath.Join(parent, "unrelated")
			content := []byte("unrelated")
			if kind == "lock-hardlink" {
				content = nil
			}
			if err := os.WriteFile(other, content, 0600); err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(parent, outputPrefix(path)+"lock")
			partial := filepath.Join(parent, outputPrefix(path)+"unexpected.partial")
			var err error
			switch kind {
			case "lock-symlink":
				err = os.Symlink(other, lock)
			case "lock-hardlink":
				err = os.Link(other, lock)
			case "partial-directory":
				err = os.Mkdir(partial, 0700)
			case "partial-symlink":
				err = os.Symlink(other, partial)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := newFile(path, func(io.Writer) error { t.Error("unsafe output started"); return nil }); err == nil {
				t.Fatal("unsafe recovery artifact accepted")
			}
			raw, err := os.ReadFile(other)
			if err != nil || !bytes.Equal(raw, content) {
				t.Fatal("unrelated file changed", string(raw), err)
			}
			if kind == "partial-directory" || kind == "partial-symlink" {
				if _, err := os.Lstat(partial); err != nil {
					t.Fatal("unexpected artifact removed", err)
				}
			}
		})
	}
}
