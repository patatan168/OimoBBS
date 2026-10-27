// pack世代切替中の実プロセス停止と、不明結果後の追記停止を検証する。
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func packVerifierFor(t *testing.T, frames ...[]byte) PackVerifier {
	t.Helper()
	return func(s PackSnapshot) ([]ThreadRecord, error) {
		b := NewPackBuilder(nil)
		for _, raw := range frames {
			f, _, e := ReadFrame(bytes.NewReader(raw))
			if e != nil {
				return nil, e
			}
			if e = b.Apply(f); e != nil {
				return nil, e
			}
		}
		expected, e := EncodePack(b.Snapshot(s.Owner, s.Key, s.Generation, s.At), 0)
		if e != nil {
			return nil, e
		}
		actual, e := EncodePack(s, 0)
		if e != nil || !bytes.Equal(expected, actual) {
			return nil, ErrCorrupt
		}
		return b.Records(), nil
	}
}
func packReply(t *testing.T, create []byte, number uint32) []byte {
	t.Helper()
	f, _, e := ReadFrame(bytes.NewReader(create))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	var c domain.Create
	if e = json.Unmarshal(op.Payload, &c); e != nil {
		t.Fatal(e)
	}
	post := c.Posts[0]
	post.Number = number
	op.Type = "append"
	op.Revision = domain.U64(number)
	op.Versions.Thread = 1
	op.After.PostCount = number
	op.After.UserCount = number
	op.After.DATBytes = domain.U64(number) * domain.U64(len(f.Records[0].DAT))
	op.Dedup.PostNumber = number
	if op.Dedup.RequestID != nil {
		id := *op.Dedup.RequestID
		id[0] = byte(number)
		op.Dedup.RequestID = &id
	} else {
		op.Dedup.Request[0] = byte(number)
	}
	op.Payload, _ = json.Marshal(domain.Append{Posts: []domain.Post{post}})
	raw, _ := json.Marshal(op)
	out, e := EncodeFrame(Frame{uint64(number), []Record{{domain.NewID(), raw, f.Records[0].DAT}}})
	if e != nil {
		t.Fatal(e)
	}
	return out
}

// TestThreadPackCrashProcess は切替の同期境界で実processを停止し、復旧・追記を検査する。
func TestThreadPackCrashProcess(t *testing.T) {
	if stage := os.Getenv("OIMO_PACK_CRASH_STAGE"); stage != "" {
		owner, frame := fixtureCreate(t)
		log, e := CreateThread(os.Getenv("OIMO_PACK_CRASH_DIR"), owner, 1, frame)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := log.PreparePack(log.State().Created, 6)
		if e != nil {
			t.Fatal(e)
		}
		log.switchPack(raw, func(at string) error {
			if at == stage {
				os.Exit(77)
			}
			return nil
		})
		t.Fatal("checkpoint not reached")
	}
	for _, stage := range []string{"pack_sync", "generation_sync", "current_sync", "current_rename", "current_directory_sync", "handle_switched"} {
		t.Run(stage, func(t *testing.T) {
			dir := privateTemp(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestThreadPackCrashProcess$")
			cmd.Env = append(os.Environ(), "OIMO_PACK_CRASH_STAGE="+stage, "OIMO_PACK_CRASH_DIR="+dir)
			out, e := cmd.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(e, &exited) || exited.ExitCode() != 77 {
				t.Fatalf("%v %s", e, out)
			}
			owner, frame := fixtureCreate(t)
			log, e := OpenThreadWithPack(dir, owner, 1, packVerifierFor(t, frame))
			if e != nil {
				t.Fatal(e)
			}
			if log.State().Revision != 1 {
				t.Fatal("lost create")
			}
			reply := packReply(t, frame, 2)
			if result := log.Append(reply); result.Status != Durable {
				t.Fatal(result)
			}
			raw, e := log.PreparePack(log.State().Created, 9)
			if e != nil {
				t.Fatal(e)
			}
			if result := log.SwitchPack(raw); result.Status != Durable {
				t.Fatal(result)
			}
			before := log.State()
			if e = log.Close(); e != nil {
				t.Fatal(e)
			}
			log, e = OpenThreadWithPack(dir, owner, 1, packVerifierFor(t, frame, reply))
			if e != nil {
				t.Fatal(e)
			}
			defer log.Close()
			if !reflect.DeepEqual(before, log.State()) {
				t.Fatal("state differs after retry")
			}
			if log.MaintenanceInfo().Codec != 2 {
				t.Fatal("archive codec not restored")
			}
		})
	}
}
func TestThreadPackUnknownStopsWriter(t *testing.T) {
	for _, stage := range []string{"pack_sync", "generation_sync", "current_sync", "current_rename", "current_directory_sync", "handle_switched"} {
		t.Run(stage, func(t *testing.T) {
			owner, frame := fixtureCreate(t)
			dir := privateTemp(t)
			log, e := CreateThread(dir, owner, 1, frame)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := log.PreparePack(log.State().Created, 6)
			if e != nil {
				t.Fatal(e)
			}
			result := log.switchPack(raw, func(at string) error {
				if at == stage {
					return errors.New("injected I/O failure")
				}
				return nil
			})
			if result.Status != Unknown || result.Err == nil {
				t.Fatal(result)
			}
			if result = log.Append(packReply(t, frame, 2)); result.Status != Unknown {
				t.Fatal("writer resumed", result)
			}
			_ = log.Close()
			recovered, e := OpenThreadWithPack(dir, owner, 1, packVerifierFor(t, frame))
			if e != nil {
				t.Fatal(e)
			}
			defer recovered.Close()
			if recovered.State().Revision != 1 {
				t.Fatal("uncertain append accepted")
			}
		})
	}
}
func TestThreadPackStaleAndCorrupt(t *testing.T) {
	owner, frame := fixtureCreate(t)
	dir := privateTemp(t)
	log, e := CreateThread(dir, owner, 1, frame)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := log.PreparePack(log.State().Created, 6)
	if e != nil {
		t.Fatal(e)
	}
	reply := packReply(t, frame, 2)
	if result := log.Append(reply); result.Status != Durable {
		t.Fatal(result)
	}
	if result := log.SwitchPack(raw); result.Status != NotWritten {
		t.Fatal("stale candidate accepted", result)
	}
	raw, e = log.PreparePack(log.State().Created, 6)
	if e != nil {
		t.Fatal(e)
	}
	if result := log.SwitchPack(raw); result.Status != Durable {
		t.Fatal(result)
	}
	_ = log.Close()
	path := filepath.Join(dir, "1", "base-000002.pack")
	raw[len(raw)-1] ^= 1
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenThreadWithPack(dir, owner, 1, packVerifierFor(t, frame, reply)); e == nil {
		t.Fatal("corrupt base fell back to old WAL")
	}
}

func TestThreadPackReclaimInterruption(t *testing.T) {
	owner, frame := fixtureCreate(t)
	dir := privateTemp(t)
	log, e := CreateThread(dir, owner, 1, frame)
	if e != nil {
		t.Fatal(e)
	}
	for range 2 {
		raw, e := log.PreparePack(log.State().Created, 6)
		if e != nil {
			t.Fatal(e)
		}
		if result := log.SwitchPack(raw); result.Status != Durable {
			t.Fatal(result)
		}
	}
	if _, e = log.reclaimOldFiles(true, func(string) error { return errors.New("stopped after unlink") }); e == nil {
		t.Fatal("missing injected error")
	}
	_ = log.Close()
	log, e = OpenThreadWithPack(dir, owner, 1, packVerifierFor(t, frame))
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	report, e := log.ReclaimOldFiles(true)
	if e != nil || report.Files != 2 {
		t.Fatal(report, e)
	}
	report, e = log.ReclaimOldFiles(true)
	if e != nil || report.Files != 0 {
		t.Fatal(report, e)
	}
}

func TestThreadPackExpiryBeforeCurrent(t *testing.T) {
	owner, frame := fixtureCreate(t)
	dir := privateTemp(t)
	log, e := CreateThread(dir, owner, 1, frame)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := log.PreparePack(log.State().Created, 6)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	result := log.SwitchPackGuarded(raw, func() error {
		calls++
		if calls == 2 {
			return errors.New("expired during sync")
		}
		return nil
	})
	if result.Status != Unknown || !log.StorageStopped() {
		t.Fatal(result)
	}
	_ = log.Close()
	current, e := os.ReadFile(filepath.Join(dir, "1", "current.json"))
	if e != nil {
		t.Fatal(e)
	}
	m, e := DecodeCurrent(current)
	if e != nil || m.Generation != 1 {
		t.Fatal("expired base installed", e)
	}
}
