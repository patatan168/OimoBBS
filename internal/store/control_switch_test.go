// 世代切替の成功・途中失敗・再起動と、旧世代保存を実ファイルで確認する。
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"oimobbs/internal/domain"
)

func switchFrame(seq uint64) []byte {
	op := ControlOperation{Schema: 1, Seq: domain.U64(seq), ExpectedSeq: domain.U64(seq - 1), Actor: domain.Actor{Kind: "system", Reason: "reserve_key"}, Mutations: []Mutation{{Collection: "key_watermark", Key: "thread", ExpectedRevision: domain.U64(seq - 1), Value: json.RawMessage(fmt.Sprintf(`{"last_reserved_key":"%d"}`, seq))}}, Result: ControlResult{Code: "reserved", Targets: []string{}}}
	raw, _ := json.Marshal(op)
	frame, _ := EncodeFrame(Frame{FirstSeq: seq, Records: []Record{{ID: domain.NewID(), JSON: raw}}})
	return frame
}
func switchFixture(t *testing.T) (*ControlLog, string) {
	t.Helper()
	dir := filepath.Join(privateTemp(t), "control")
	log, err := CreateControl(dir, Header{Kind: 2, Owner: domain.NewID(), Generation: 1}, switchFrame(1), snapshotValidator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	if r := log.Append(switchFrame(2)); r.Status != Durable {
		t.Fatal(r)
	}
	return log, dir
}
func switchBytes(t *testing.T, log *ControlLog, level int) []byte {
	t.Helper()
	h := log.header
	h.Generation++
	h.BaseSeq = uint64(log.state.Seq)
	raw, err := EncodeControlSnapshot(h, log.State(), level, snapshotValidator)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestControlSwitchRoundTrip(t *testing.T) {
	for _, level := range []int{0, 1, 6, 9} {
		t.Run(fmt.Sprint(level), func(t *testing.T) {
			log, dir := switchFixture(t)
			original, _ := os.ReadFile(filepath.Join(dir, "control-000001.wal"))
			before := log.State()
			if r := log.SwitchSnapshot(switchBytes(t, log, level)); r.Status != Durable || r.Err != nil {
				t.Fatal(r)
			}
			if log.header.Generation != 2 || !reflect.DeepEqual(log.State(), before) {
				t.Fatal("state changed")
			}
			if r := log.Append(switchFrame(3)); r.Status != Durable {
				t.Fatal(r)
			}
			// さらに次の世代へ切替え、同じハンドルの追記を継続する。
			if r := log.SwitchSnapshot(switchBytes(t, log, level)); r.Status != Durable {
				t.Fatal(r)
			}
			if r := log.Append(switchFrame(4)); r.Status != Durable {
				t.Fatal(r)
			}
			owner := log.header.Owner
			log.Close()
			reopened, err := OpenControl(dir, 2, owner, 0, snapshotValidator)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if reopened.State().Seq != 4 || reopened.header.Generation != 3 {
				t.Fatal("wrong recovery")
			}
			if r := reopened.Append(switchFrame(5)); r.Status != Durable {
				t.Fatal(r)
			}
			got, _ := os.ReadFile(filepath.Join(dir, "control-000001.wal"))
			if !bytes.Equal(got, original) {
				t.Fatal("old generation changed")
			}
		})
	}
}
func TestControlSwitchFailureBoundaries(t *testing.T) {
	for _, stage := range []string{"snapshot_sync", "generation_sync", "current_sync", "current_rename", "current_directory_sync"} {
		t.Run(stage, func(t *testing.T) {
			log, dir := switchFixture(t)
			raw := switchBytes(t, log, 6)
			injected := errors.New("injected boundary failure")
			r := log.switchSnapshot(raw, func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			})
			if r.Status != Unknown || !errors.Is(r.Err, injected) {
				t.Fatal(r)
			}
			if log.Append(switchFrame(3)).Status != Unknown || log.SwitchSnapshot(raw).Status != Unknown {
				t.Fatal("writer continued")
			}
			owner := log.header.Owner
			log.Close()
			reopened, err := OpenControl(dir, 2, owner, 0, snapshotValidator)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			want := uint64(1)
			if stage == "current_rename" || stage == "current_directory_sync" {
				want = 2
			}
			if reopened.header.Generation != want || reopened.State().Seq != 2 {
				t.Fatal("wrong generation")
			}
			if r := reopened.Append(switchFrame(3)); r.Status != Durable {
				t.Fatal(r)
			}
		})
	}
}
func TestControlSwitchRejectsBeforeWriting(t *testing.T) {
	for _, bad := range []string{"corrupt", "stale", "existing", "validator"} {
		t.Run(bad, func(t *testing.T) {
			log, dir := switchFixture(t)
			raw := switchBytes(t, log, 6)
			switch bad {
			case "corrupt":
				raw[len(raw)-1] ^= 1
			case "stale":
				if r := log.Append(switchFrame(3)); r.Status != Durable {
					t.Fatal(r)
				}
			case "existing":
				if err := os.WriteFile(filepath.Join(dir, "control-000002.wal"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "validator":
				log.validator = func(string, string, json.RawMessage, json.RawMessage) error { return ErrCorrupt }
			}
			before, _ := os.ReadFile(filepath.Join(dir, "control.current"))
			if r := log.SwitchSnapshot(raw); r.Status != NotWritten || r.Err == nil {
				t.Fatal(r)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "control.current"))
			if !bytes.Equal(before, after) || log.writer.stopped {
				t.Fatal("preflight changed current or stopped writer")
			}
			if _, err := os.Stat(filepath.Join(dir, "control-000002.snap")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("snapshot written")
			}
		})
	}
}

// 子processをdeferの実行なしで終了し、一時fileが残る実際の復旧経路を検査する。
func TestControlSwitchProcessExit(t *testing.T) {
	if stage := os.Getenv("OIMO_SWITCH_TEST_STAGE"); stage != "" {
		var owner domain.ID
		encoded, _ := json.Marshal(os.Getenv("OIMO_SWITCH_TEST_OWNER"))
		if err := json.Unmarshal(encoded, &owner); err != nil {
			t.Fatal(err)
		}
		log, err := OpenControl(os.Getenv("OIMO_SWITCH_TEST_DIR"), 2, owner, 0, snapshotValidator)
		if err != nil {
			t.Fatal(err)
		}
		log.switchSnapshot(switchBytes(t, log, 6), func(at string) error {
			if at == stage {
				os.Exit(77)
			}
			return nil
		})
		t.Fatal("exit boundary not reached")
	}
	for _, stage := range []string{"snapshot_sync", "generation_sync", "current_sync", "current_rename", "current_directory_sync"} {
		t.Run(stage, func(t *testing.T) {
			log, dir := switchFixture(t)
			owner := log.header.Owner
			log.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestControlSwitchProcessExit$")
			cmd.Env = append(os.Environ(), "OIMO_SWITCH_TEST_STAGE="+stage, "OIMO_SWITCH_TEST_DIR="+dir, "OIMO_SWITCH_TEST_OWNER="+owner.String())
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("%v %s", err, output)
			}
			recovered, err := OpenControl(dir, 2, owner, 0, snapshotValidator)
			if err != nil {
				t.Fatal(err)
			}
			defer recovered.Close()
			want := uint64(1)
			if stage == "current_rename" || stage == "current_directory_sync" {
				want = 2
			}
			if recovered.header.Generation != want || recovered.State().Seq != 2 {
				t.Fatal("wrong recovered state")
			}
			if r := recovered.Append(switchFrame(3)); r.Status != Durable {
				t.Fatal(r)
			}
		})
	}
}

func TestControlSwitchMissingSnapshotDoesNotFallback(t *testing.T) {
	log, dir := switchFixture(t)
	if r := log.SwitchSnapshot(switchBytes(t, log, 6)); r.Status != Durable {
		t.Fatal(r)
	}
	owner := log.header.Owner
	log.Close()
	if err := os.Remove(filepath.Join(dir, "control-000002.snap")); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenControl(dir, 2, owner, 0, snapshotValidator); err == nil {
		reopened.Close()
		t.Fatal("missing snapshot fell back to an old generation")
	}
}

// 一致する途中ファイルだけを補完し、異内容や過長ファイルを上書きしない。
func TestControlSwitchResumePrefix(t *testing.T) {
	for _, mode := range []string{"prefix", "wrong", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			log, dir := switchFixture(t)
			raw := switchBytes(t, log, 6)
			partial := append([]byte(nil), raw[:len(raw)/2]...)
			if mode == "wrong" {
				partial[0] ^= 1
			}
			if mode == "oversize" {
				partial = append(append([]byte(nil), raw...), 0)
			}
			path := filepath.Join(dir, "control-000002.snap")
			if err := os.WriteFile(path, partial, 0600); err != nil {
				t.Fatal(err)
			}
			result := log.ResumeSnapshot(raw)
			if mode == "prefix" {
				if result.Status != Durable || result.Err != nil {
					t.Fatal(result)
				}
			} else {
				if result.Status == Durable || result.Err == nil {
					t.Fatal("conflict accepted")
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, partial) {
					t.Fatal("conflict overwritten", err)
				}
			}
		})
	}
}
