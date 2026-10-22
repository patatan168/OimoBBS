// 稼働所有者の確定prefixを固定し、追記・世代切替・unlink後も正しくコピーする。
package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestThreadPinnedBackup(t *testing.T) {
	parent := privateTemp(t)
	owner, create := fixtureCreate(t)
	log, e := CreateThread(parent, owner, 1700000000, create)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	pin, e := log.PinBackup(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	if _, e := log.PinBackup(context.Background()); !errors.Is(e, ErrBackupPinBusy) {
		t.Fatal("duplicate pin", e)
	}
	original, e := os.ReadFile(log.file.Name())
	if e != nil {
		t.Fatal(e)
	}
	started, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	target := filepath.Join(privateTemp(t), "1700000000")
	done := make(chan error, 1)
	go func() {
		cut, e := pin.copy(context.Background(), target, func(stage string) error {
			if stage == "backup:copy_start" {
				close(started)
				<-release
			}
			return nil
		})
		if e == nil && cut.Sequence != 1 {
			e = errors.New("capture advanced")
		}
		done <- e
	}()
	<-started
	reply := packReply(t, create, 2)
	if r := log.Append(reply); r.Status != Durable {
		t.Fatal(r)
	}
	pack, e := log.PreparePack(log.State().Created, 6)
	if e != nil {
		t.Fatal(e)
	}
	if r := log.SwitchPack(pack); r.Status != Durable {
		t.Fatal(r)
	}
	if _, e := log.ReclaimOldFiles(true); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(log.dir, "delta-000001.wal")); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(filepath.Join(target, "delta-000001.wal"))
	if e != nil || !bytes.Equal(got, original) {
		t.Fatal("prefix changed", e)
	}
	restored, e := OpenThread(filepath.Dir(target), owner, 1700000000)
	if e != nil {
		t.Fatal(e)
	}
	if restored.State().Revision != 1 {
		t.Fatal(restored.State())
	}
	restored.Close()
	next, e := log.PinBackup(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	// pack付きの組を固定した後、さらに切り替えて元packも回収する。
	nextTarget := filepath.Join(privateTemp(t), "1700000000")
	pack, e = log.PreparePack(log.State().Created, 9)
	if e != nil {
		t.Fatal(e)
	}
	if r := log.SwitchPack(pack); r.Status != Durable {
		t.Fatal(r)
	}
	if _, e := log.ReclaimOldFiles(true); e != nil {
		t.Fatal(e)
	}
	cut, e := next.Copy(context.Background(), nextTarget)
	if e != nil || cut.Sequence != 2 || len(cut.Files) != 2 {
		t.Fatal(cut, e)
	}
	restored, e = OpenThreadWithPack(filepath.Dir(nextTarget), owner, 1700000000, packVerifierFor(t, create, reply))
	if e != nil {
		t.Fatal(e)
	}
	restored.Close()
	if _, e = next.Copy(context.Background(), filepath.Join(privateTemp(t), "again")); e == nil {
		t.Fatal("reused consumed pin")
	}
}

func TestControlPinnedBackup(t *testing.T) {
	log, dir := switchFixture(t)
	if r := log.SwitchSnapshot(switchBytes(t, log, 6)); r.Status != Durable {
		t.Fatal(r)
	}
	pin, e := log.PinBackup(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	if r := log.Append(switchFrame(3)); r.Status != Durable {
		t.Fatal(r)
	}
	if r := log.SwitchSnapshot(switchBytes(t, log, 9)); r.Status != Durable {
		t.Fatal(r)
	}
	for _, name := range []string{"control-000002.wal", "control-000002.snap"} {
		if e := os.Remove(filepath.Join(dir, name)); e != nil {
			t.Fatal(e)
		}
	}
	target := filepath.Join(privateTemp(t), "copy")
	cut, e := pin.Copy(context.Background(), target)
	if e != nil || cut.Sequence != 2 || len(cut.Files) != 2 {
		t.Fatal(cut, e)
	}
	restored, e := OpenControlWithValidators(target, log.header.Kind, log.header.Owner, 0, snapshotValidator, snapshotValidator)
	if e != nil {
		t.Fatal(e)
	}
	if restored.State().Seq != 2 {
		t.Fatal(restored.State())
	}
	restored.Close()
}

func TestPinnedBackupFailures(t *testing.T) {
	parent := privateTemp(t)
	owner, create := fixtureCreate(t)
	log, e := CreateThread(parent, owner, 1700000000, create)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := log.PinBackup(canceled); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, kind := range []string{"canceled", "existing", "inside-source", "tampered-base", "short-prefix", "write-stop", "symlink-parent"} {
		t.Run(kind, func(t *testing.T) {
			local, err := CreateThread(privateTemp(t), owner, 1700000000, create)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			if kind == "tampered-base" {
				raw, err := local.PreparePack(local.State().Created, 6)
				if err != nil {
					t.Fatal(err)
				}
				if r := local.SwitchPack(raw); r.Status != Durable {
					t.Fatal(r)
				}
			}
			pin, err := local.PinBackup(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer pin.Close()
			target := filepath.Join(privateTemp(t), "copy")
			copyCtx := ctx
			if kind == "canceled" {
				copyCtx = canceled
			}
			if kind == "existing" {
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "inside-source" {
				target = filepath.Join(local.dir, "copy")
			}
			if kind == "tampered-base" {
				path := filepath.Join(local.dir, local.manifest.Base.File)
				f, err := os.OpenFile(path, os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte{0xff}, 0)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind == "short-prefix" {
				if err := os.Truncate(local.file.Name(), 64); err != nil {
					t.Fatal(err)
				}
			}

			if kind == "symlink-parent" {
				sub := filepath.Join(local.dir, "sub")
				if err := os.Mkdir(sub, 0700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(privateTemp(t), "link")
				if err := os.Symlink(local.dir, link); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(link, "sub", "copy")
			}
			stop := errors.New("stop copy")
			cut, err := pin.copy(copyCtx, target, func(string) error {
				if kind == "write-stop" {
					return stop
				}
				return nil
			})
			if err == nil || len(cut.Current) != 0 || len(cut.Files) != 0 {
				t.Fatal(cut, err)
			}
			if _, err := os.Stat(filepath.Join(target, "current.json")); !os.IsNotExist(err) {
				t.Fatal("completion installed after failure", err)
			}
			if local.backupPinned.Load() {
				t.Fatal("pin leaked")
			}
			if kind == "write-stop" {
				if _, err := os.Stat(target); err != nil {
					t.Fatal("failed output removed", err)
				}
			}
		})
	}
	pin, e := log.PinBackup(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = pin.Close(); e != nil {
		t.Fatal(e)
	}
	if e = pin.Close(); e != nil {
		t.Fatal(e)
	}
	log.writer.stopped = true
	if _, e = log.PinBackup(ctx); e == nil {
		t.Fatal("uncertain owner pinned")
	}
	var zero PinnedBackup
	if e = zero.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestPinnedBackupManagement(t *testing.T) {
	owner, create := fixtureCreate(t)
	log, e := CreateThread(privateTemp(t), owner, 1700000000, create)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	if _, e := log.PinBackupLimited(context.Background(), 64); !errors.Is(e, ErrBackupPinBudget) || log.backupPinned.Load() {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pin, e := log.PinBackup(ctx)
	if e != nil {
		t.Fatal(e)
	}
	released := make(chan struct{})
	if e = pin.Manage(ctx, func() { close(released) }); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("idle pin not released")
	}
	if log.backupPinned.Load() {
		t.Fatal("owner flag not released before reservation")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	pin, e = log.PinBackup(ctx)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	if e = pin.Manage(ctx, func() { count++ }); e != nil {
		t.Fatal(e)
	}
	cut, e := pin.copy(context.Background(), filepath.Join(privateTemp(t), "copy"), func(string) error { cancel(); return nil })
	if e == nil || len(cut.Files) != 0 || count != 1 || log.backupPinned.Load() {
		t.Fatal(cut, e, count)
	}
	if e = pin.Close(); e != nil || count != 1 {
		t.Fatal(e, count)
	}
}

func TestControlBackupPinBudget(t *testing.T) {
	log, _ := switchFixture(t)
	if r := log.SwitchSnapshot(switchBytes(t, log, 6)); r.Status != Durable {
		t.Fatal(r)
	}
	ctx := context.Background()
	p, e := log.PinBackup(ctx)
	if e != nil {
		t.Fatal(e)
	}
	bytes := p.ReferenceBytes()
	p.Close()
	if _, e = log.PinBackupLimited(ctx, bytes-1); !errors.Is(e, ErrBackupPinBudget) || log.backupPinned.Load() {
		t.Fatal(e)
	}
	p, e = log.PinBackupLimited(ctx, bytes)
	if e != nil || p.ReferenceBytes() != bytes {
		t.Fatal(e)
	}
	p.Close()
}
