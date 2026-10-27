// 共有本文WALの再実行・障害・checkpointと、元WAL形式による独立復旧を検査する。
package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"testing"
)

func newThreadGroupTest(t *testing.T) (*ThreadCommitGroup, []ThreadAppend, []byte) {
	t.Helper()
	owner, create := fixtureCreate(t)
	root := privateTemp(t)
	g := NewThreadCommitGroup(root, owner)
	t.Cleanup(func() { g.Close() })
	var batches []ThreadAppend
	for key := uint64(1); key <= 3; key++ {
		log, err := CreateThread(root, owner, key, create)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { log.Close() })
		batches = append(batches, ThreadAppend{log, [][]byte{packReply(t, create, 2)}})
	}
	return g, batches, create
}

func TestThreadGroupCheckpointBoundaries(t *testing.T) {
	for _, boundary := range []string{"backup", "pin", "pack", "append", "append-batch", "close"} {
		t.Run(boundary, func(t *testing.T) {
			g, batches, create := newThreadGroupTest(t)
			for seq := uint32(2); seq <= 3; seq++ {
				for i := range batches {
					batches[i].Frames = [][]byte{packReply(t, create, seq)}
				}
				if r := g.Commit(batches); r.Status != Durable {
					t.Fatal(r)
				}
			}
			if g.Stats().Syncs != 2 {
				t.Fatal("共有同期回数", g.Stats())
			}
			for _, batch := range batches {
				if batch.Log.CommitStats().Syncs != 1 || batch.Log.State().Revision != 3 {
					t.Fatal("個別同期を行った、または候補を失った")
				}
			}
			log := batches[0].Log
			if result := log.Append(create); result.Status != NotWritten {
				t.Fatal("不正な個別追記を採用した", result)
			}
			if result := log.AppendBatch([][]byte{create}); result.Status != NotWritten || g.file == nil {
				t.Fatal("不正な候補でcheckpointした", result)
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := log.BackupCapture(cancelled); !errors.Is(err, context.Canceled) || g.file == nil {
				t.Fatal("取消済み捕捉でcheckpointした", err)
			}
			if _, err := log.PinBackupLimited(context.Background(), 0); !errors.Is(err, ErrBackupPinBudget) || g.file == nil {
				t.Fatal("無効な固定予算でcheckpointした", err)
			}
			var err error
			switch boundary {
			case "backup":
				_, err = log.BackupCapture(context.Background())
			case "pin":
				var pin *PinnedBackup
				pin, err = log.PinBackup(context.Background())
				if err == nil {
					err = pin.Close()
				}
			case "pack":
				_, err = log.PreparePack(log.State().Created, 0)
			case "append":
				err = log.Append(packReply(t, create, 4)).Err
			case "append-batch":
				err = log.AppendBatch([][]byte{packReply(t, create, 4)}).Err
			case "close":
				err = log.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(filepath.Join(g.parent, ThreadGroupFile)); !os.IsNotExist(err) {
				t.Fatal("checkpoint後も共有WALが残った", err)
			}
			for _, batch := range batches {
				if batch.Log.group != nil || batch.Log.CommitStats().Syncs < 2 {
					t.Fatal("共有WAL削除前に全本文を同期していない")
				}
			}
		})
	}
}

func TestThreadGroupReplayLostAndTornBodies(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			g, batches, create := newThreadGroupTest(t)
			prefix := map[uint64][]byte{}
			for _, batch := range batches {
				raw, err := os.ReadFile(batch.Log.file.Name())
				if err != nil {
					t.Fatal(err)
				}
				prefix[batch.Log.header.Key] = raw
			}
			frames := map[uint64][][]byte{}
			for seq := uint32(2); seq <= 3; seq++ {
				for i := range batches {
					frame := packReply(t, create, seq)
					batches[i].Frames = [][]byte{frame}
					frames[batches[i].Log.header.Key] = append(frames[batches[i].Log.header.Key], frame)
				}
				if result := g.Commit(batches); result.Status != Durable {
					t.Fatal(result)
				}
			}
			// 未同期の個別末尾だけを失う電源断相当の状態を合成する。共有WALは保持する。
			if err := g.file.Close(); err != nil {
				t.Fatal(err)
			}
			g.file, g.stopped = nil, true
			before := map[string][]byte{}
			for i, batch := range batches {
				path := batch.Log.file.Name()
				batch.Log.file.Close()
				raw := bytes.Clone(prefix[batch.Log.header.Key])
				if i == 1 {
					raw = append(raw, 1, 2, 3, 4, 5) // 未同期末尾の破損。
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				before[path] = raw
			}
			calls := 0
			authorize := func(key uint64, raw []byte) error {
				calls++
				for path, original := range before {
					actual, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(original, actual) {
						t.Fatal("全件照合前に本文を変更した", err)
					}
				}
				matched := false
				for _, frame := range frames[key] {
					matched = matched || bytes.Equal(frame, raw)
				}
				if !matched || reject && key == 3 {
					return ErrCorrupt
				}
				return nil
			}
			err := RecoverThreadCommitGroup(g.parent, g.owner, authorize)
			if reject {
				if err == nil {
					t.Fatal("署名不一致を採用した")
				}
				for path, raw := range before {
					actual, _ := os.ReadFile(path)
					if !bytes.Equal(actual, raw) {
						t.Fatal("拒否時に本文を変更した")
					}
				}
				return
			}
			if err != nil || calls != 6 {
				t.Fatal(err, calls)
			}
			for _, batch := range batches {
				log, err := OpenThread(g.parent, g.owner, batch.Log.header.Key)
				if err != nil {
					t.Fatal(err)
				}
				defer log.Close()
				if log.State().Revision != 3 {
					t.Fatal("共有同期済み本文を失った")
				}
			}
			if err := RecoverThreadCommitGroup(g.parent, g.owner, authorize); err != nil {
				t.Fatal("復旧が冪等でない", err)
			}
		})
	}
}

type groupFaultFile struct {
	*os.File
	short    bool
	syncErr  error
	writeErr error
}

func (f groupFaultFile) Write(raw []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return f.File.Write(raw[:len(raw)/2])
	}
	return f.File.Write(raw)
}

func (f groupFaultFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func TestThreadGroupFailures(t *testing.T) {
	for _, failure := range []string{"invalid", "duplicate", "shared-short", "shared-write", "shared-sync", "checkpoint"} {
		t.Run(failure, func(t *testing.T) {
			g, batches, create := newThreadGroupTest(t)
			injected := errors.New("injected group failure")
			switch failure {
			case "invalid":
				batches[2].Frames = [][]byte{create}
			case "duplicate":
				batches[2].Log = batches[0].Log
			case "shared-short", "shared-write", "shared-sync":
				if err := g.open(); err != nil {
					t.Fatal(err)
				}
				fault := groupFaultFile{File: g.file.(*os.File)}
				fault.short = failure == "shared-short"
				if failure == "shared-write" {
					fault.writeErr = injected
				}
				if failure == "shared-sync" {
					fault.syncErr = injected
				}
				g.file = fault
			}
			result := g.Commit(batches)
			if failure == "checkpoint" {
				if result.Status != Durable {
					t.Fatal(result)
				}
				batches[1].Log.writer.file = &faultWriter{syncErr: injected}
				if err := g.Checkpoint(); !errors.Is(err, injected) {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(g.parent, ThreadGroupFile)); err != nil {
					t.Fatal("本文同期失敗で再実行WALを失った", err)
				}
				return
			}
			want := Unknown
			if failure == "invalid" || failure == "duplicate" {
				want = NotWritten
				if g.Stats().Writes != 0 {
					t.Fatal("不正候補で保存を開始した")
				}
			}
			if result.Status != want {
				t.Fatal(result, want)
			}
			for _, batch := range batches {
				if batch.Log.State().Revision != 1 {
					t.Fatal("失敗時に候補を交換した")
				}
				if want == Unknown && !batch.Log.writer.stopped {
					t.Fatal("別参加者を停止しなかった")
				}
			}
			if want == Unknown && g.Commit(batches).Status != Unknown {
				t.Fatal("不明結果後に保存を再開した")
			}
		})
	}
}

func TestThreadGroupReplayRejectsInvalidMetadata(t *testing.T) {
	for _, corrupt := range []string{"owner", "duplicate", "offset", "generation", "block", "prefix", "extra-tail"} {
		t.Run(corrupt, func(t *testing.T) {
			g, batches, _ := newThreadGroupTest(t)
			if result := g.Commit(batches); result.Status != Durable {
				t.Fatal(result)
			}
			g.file.Close()
			g.file, g.stopped = nil, true
			path := filepath.Join(g.parent, ThreadGroupFile)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			records, err := decodeThreadGroups(raw)
			if err != nil {
				t.Fatal(err)
			}
			switch corrupt {
			case "owner":
				records[0].Owner = domain.NewID()
			case "duplicate":
				records[0].Writes[2] = records[0].Writes[0]
			case "offset":
				records[0].Writes[2].Offset++
			case "generation":
				records[0].Writes[2].Generation++
			case "block":
				records[0].Writes[2].Block = []byte("AAAA")
			case "prefix", "extra-tail":
				body, err := os.ReadFile(batches[2].Log.file.Name())
				if err != nil {
					t.Fatal(err)
				}
				if corrupt == "prefix" {
					body[65] ^= 1
				} else {
					// 個別反映前でも、共有WALが宣言する論理末尾より後ろは拒否する。
					body = append(body, make([]byte, int(batches[2].Log.end)-len(body)+1)...)
				}
				if err = os.WriteFile(batches[2].Log.file.Name(), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			raw, err = encodeThreadGroup(records[0])
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			before := map[string][]byte{path: raw}
			for _, batch := range batches {
				body, err := os.ReadFile(batch.Log.file.Name())
				if err != nil {
					t.Fatal(err)
				}
				before[batch.Log.file.Name()] = body
			}
			if err = RecoverThreadCommitGroup(g.parent, g.owner, func(uint64, []byte) error { return nil }); err == nil {
				t.Fatal("不正な再実行対象を採用した")
			}
			for file, original := range before {
				actual, err := os.ReadFile(file)
				if err != nil || !bytes.Equal(actual, original) {
					t.Fatal("拒否時にファイルを変更した", err)
				}
			}
		})
	}
}

func TestThreadGroupBatchLimitCheckpoint(t *testing.T) {
	g, batches, create := newThreadGroupTest(t)
	for seq := uint32(2); seq <= 66; seq++ {
		for i := range batches {
			batches[i].Frames = [][]byte{packReply(t, create, seq)}
		}
		if result := g.Commit(batches); result.Status != Durable {
			t.Fatal(seq, result)
		}
	}
	if g.batches != 65 || g.frames != 195 || len(g.dirty) != len(batches) || g.Stats().Syncs != 65 {
		t.Fatal("小さいbatchをframe予算より早くcheckpointした", g.batches, g.frames, g.Stats())
	}
	for _, batch := range batches {
		if batch.Log.CommitStats().Syncs != 1 {
			t.Fatal("小さいbatchの回数だけで個別本文を同期した")
		}
	}
}

func TestThreadGroupReplayAfterPackSwitch(t *testing.T) {
	g, batches, create := newThreadGroupTest(t)
	second := batches[0].Frames[0]
	if result := g.Commit(batches); result.Status != Durable {
		t.Fatal(result)
	}
	log := batches[0].Log
	raw, err := log.PreparePack(log.State().Created, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result := log.SwitchPack(raw); result.Status != Durable {
		t.Fatal(result)
	}
	third := packReply(t, create, 3)
	if result := g.Commit([]ThreadAppend{{log, [][]byte{third}}}); result.Status != Durable {
		t.Fatal(result)
	}
	g.file.Close()
	g.file, g.stopped = nil, true
	path := log.file.Name()
	log.file.Close()
	if err := os.Truncate(path, 64); err != nil {
		t.Fatal(err)
	}
	if err := RecoverThreadCommitGroup(g.parent, g.owner, func(key uint64, frame []byte) error {
		if key != log.header.Key || !bytes.Equal(frame, third) {
			return ErrCorrupt
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenThreadWithPack(g.parent, g.owner, log.header.Key, packVerifierFor(t, create, second))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.State().Revision != 3 {
		t.Fatal("pack世代の共有本文を復旧できない")
	}
}

func FuzzThreadGroupEncoding(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("OIMOGRP2"))
	seed, err := encodeThreadGroup(threadGroupRecord{Owner: domain.NewID(), Writes: []threadGroupWrite{{Key: 1, Generation: 1, Offset: 64, Block: []byte("AAAA")}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxThreadGroupBytes {
			return
		}
		records, err := decodeThreadGroups(raw)
		if err != nil {
			return
		}
		for _, record := range records {
			encoded, err := encodeThreadGroup(record)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := decodeThreadGroups(encoded)
			if err != nil || len(roundtrip) != 1 {
				t.Fatal("受理した共有WALを再読取できない", err)
			}
		}
	})
}
