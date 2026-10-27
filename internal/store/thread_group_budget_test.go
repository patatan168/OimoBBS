// 小batchの回数と独立して復旧量を制限し、上限を超える保存をcheckpointへ分割する。
package store

import (
	"bytes"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"testing"
)

func TestThreadGroupFrameBudgetCheckpointAndRecoveryLimit(t *testing.T) {
	g, batches, create := newThreadGroupTest(t)
	for key := uint64(4); key <= 8; key++ {
		log, err := CreateThread(g.parent, g.owner, key, create)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { log.Close() })
		batches = append(batches, ThreadAppend{Log: log})
	}
	var seq uint32 = 2
	for range 64 {
		var frames [][]byte
		for range 8 {
			frames = append(frames, packReply(t, create, seq))
			seq++
		}
		for i := range batches {
			batches[i].Frames = frames
		}
		if result := g.Commit(batches); result.Status != Durable {
			t.Fatal(result)
		}
	}
	if g.frames != maxThreadGroupFrames || g.batches != 64 {
		t.Fatal("frame予算を使い切れない", g.frames, g.batches)
	}
	for i := range batches {
		batches[i].Frames = [][]byte{packReply(t, create, seq)}
		if batches[i].Log.CommitStats().Syncs != 1 {
			t.Fatal("frame予算前にcheckpointした")
		}
	}
	// 符号化record数だけは小さくても、復旧の総frame数は4096を超えてはならない。
	plans, err := g.prepare(batches)
	if err != nil {
		t.Fatal(err)
	}
	record := threadGroupRecord{Owner: g.owner}
	for _, plan := range plans {
		record.Writes = append(record.Writes, plan.write)
	}
	last, err := encodeThreadGroup(record)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(g.parent, ThreadGroupFile))
	if err != nil {
		t.Fatal(err)
	}
	records, err := decodeThreadGroups(append(raw, last...))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	if _, err := prepareThreadGroupReplay(records, g.owner, func(uint64, []byte) error { checked++; return nil }); err == nil || checked > maxThreadGroupFrames {
		t.Fatal("復旧frame予算を超えて検証した", checked, err)
	}
	if result := g.Commit(batches); result.Status != Durable || g.batches != 1 || g.frames != 8 {
		t.Fatal("frame上限で自動checkpointしなかった", result, g.batches, g.frames)
	}
	for _, batch := range batches {
		if batch.Log.CommitStats().Syncs != 2 {
			t.Fatal("共有WALを区切る前に本文を同期しなかった")
		}
	}
}

func TestThreadGroupGlobalTargetLimit(t *testing.T) {
	record := threadGroupRecord{Owner: domain.NewID()}
	for key := uint64(1); key <= MaxCommitFrames; key++ {
		record.Writes = append(record.Writes, threadGroupWrite{Key: domain.U64(key), Generation: 1, Offset: 64, Block: []byte{1}})
	}
	raw, err := encodeThreadGroup(record)
	if err != nil {
		t.Fatal(err)
	}
	if records, err := decodeThreadGroups(bytes.Repeat(raw, 64)); err != nil || len(records) != 64 {
		t.Fatal("従来の最大metadataを拒否した", err)
	}
	if _, err := decodeThreadGroups(bytes.Repeat(raw, 65)); err == nil {
		t.Fatal("metadata上限を超えた")
	}
}

func TestThreadGroupExpandedByteBudgetCheckpoint(t *testing.T) {
	g, batches, create := newThreadGroupTest(t)
	if result := g.Commit(batches); result.Status != Durable {
		t.Fatal(result)
	}
	size := 0
	for i := range batches {
		batches[i].Frames = [][]byte{packReply(t, create, 3)}
		size += len(batches[i].Frames[0])
	}
	// 小さい実ファイルで展開総量の境界を再現する。件数・圧縮後bytesは上限未満。
	g.frameBytes = maxThreadGroupFrameBytes - size + 1
	if result := g.Commit(batches); result.Status != Durable || g.batches != 1 || g.frameBytes != size {
		t.Fatal("圧縮前byte予算でcheckpointしなかった", result, g.frameBytes)
	}
	for _, batch := range batches {
		if batch.Log.CommitStats().Syncs != 2 {
			t.Fatal("展開byte予算で本文を同期しなかった")
		}
	}
}
