// 分割した既存blockのbyte同一性・旧reader復号と、失敗前の無書込み・一回同期を検証する。
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"runtime"
	"strings"
	"testing"
)

func parallelWALFrames(t *testing.T) [][]byte {
	t.Helper()
	frames := make([][]byte, 32)
	for i := range frames {
		value, _ := json.Marshal(map[string]string{"text": strings.Repeat(fmt.Sprintf("本文-%d/", i), 1000)})
		frames[i] = independentControlFrame(t, domain.U64(i+1), fmt.Sprint(i), value)
	}
	return frames
}

func TestParallelWALRetainsCanonicalBlocksAndFrames(t *testing.T) {
	frames := parallelWALFrames(t)
	for _, cpus := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(cpus), func(t *testing.T) {
			previous := runtime.GOMAXPROCS(cpus)
			defer runtime.GOMAXPROCS(previous)
			chunk := 16
			if cpus == 8 {
				chunk = 8
			}
			var expected []byte
			for start := 0; start < len(frames); start += chunk {
				block, err := EncodeWALBlock(frames[start : start+chunk])
				if err != nil {
					t.Fatal(err)
				}
				expected = append(expected, block...)
			}
			raw, err := encodeParallelWAL(frames)
			if err != nil || !bytes.Equal(raw, expected) {
				t.Fatal("block bytes changed", err)
			}
			reader := bytes.NewReader(raw)
			index := 0
			for {
				decoded, _, err := ReadWALBlock(reader)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range decoded {
					canonical, err := EncodeFrame(f)
					if err != nil || !bytes.Equal(canonical, frames[index]) {
						t.Fatal("raw frame changed", index, err)
					}
					index++
				}
			}
			if index != len(frames) {
				t.Fatal(index)
			}
		})
	}
}

func TestParallelWALCommitFaultBoundaries(t *testing.T) {
	for _, mode := range []string{"accept", "invalid", "before", "write", "short", "sync"} {
		t.Run(mode, func(t *testing.T) {
			frames := parallelWALFrames(t)
			f := &faultWriter{}
			var before func(int64) error
			switch mode {
			case "invalid":
				frames[25][8] ^= 1
			case "before":
				before = func(int64) error { return errors.New("reject size") }
			case "write":
				f.writeErr = errors.New("write")
			case "short":
				f.short = true
			case "sync":
				f.syncErr = errors.New("sync")
			}
			w := NewWriter(f)
			result := w.CommitBatchParallel(frames, before)
			switch mode {
			case "accept":
				if result.Status != Durable || w.Stats().Writes != 1 || w.Stats().Syncs != 1 {
					t.Fatal(result, w.Stats())
				}
			case "invalid", "before":
				if result.Status != NotWritten || f.writes != 0 {
					t.Fatal(result, f.writes)
				}
			default:
				if result.Status != Unknown || f.writes != 1 {
					t.Fatal(result, f.writes)
				}
				if retry := w.CommitBatchParallel(frames, nil); retry.Status != Unknown || f.writes != 1 {
					t.Fatal("failed writer resumed")
				}
			}
		})
	}
}
