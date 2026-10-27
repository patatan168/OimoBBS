// 複数の独立frameを持つpackで、並列展開の順序・範囲・破損拒否を検証する。
package store

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/testutil"
)

// largePackFixture は本文・JSONとも複数ブロックになる保存データを生成する。
func largePackFixture(t testing.TB) ([]byte, []byte) {
	t.Helper()
	s, err := DecodePack(packFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	post := s.State.Posts[1]
	s.State.Posts = s.State.Posts[:1]
	s.State.Lines = s.State.Lines[:1]
	s.Origins = s.Origins[:1]
	s.Dedup, s.Audit = nil, nil
	offset := len(s.State.Lines[0])
	for i := range 128 {
		p := post
		p.Number = uint32(i + 2)
		p.Body = fmt.Sprintf("post %d ", i) + strings.Repeat("parallel zstd decode and validate ", 120)
		line := []byte("name<><>date<>" + p.Body + "<>\n")
		p.DATOffset, p.DATLength = uint32(offset), uint32(len(line))
		offset += len(line)
		s.State.Posts = append(s.State.Posts, p)
		s.State.Lines = append(s.State.Lines, line)
		s.Origins = append(s.Origins, s.State.Revision)
	}
	s.State.After.PostCount = uint32(len(s.State.Posts))
	s.State.After.UserCount = s.State.After.PostCount
	s.State.After.DATBytes = domain.U64(offset)
	packed, err := EncodePack(s, 6)
	if err != nil {
		t.Fatal(err)
	}
	return packed, bytes.Join(s.State.Lines, nil)
}

func TestParallelPackDecode(t *testing.T) {
	packed, dat := largePackFixture(t)
	input := bytes.Clone(packed)
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	want, err := DecodePack(packed)
	if err != nil {
		t.Fatal(err)
	}
	_, _, blocks, err := parsePack(packed)
	if err != nil || len(blocks) < 4 {
		t.Fatal("fixture needs at least four independent frames", len(blocks), err)
	}
	for _, cores := range []int{1, 2, 4} {
		runtime.GOMAXPROCS(cores)
		var readers sync.WaitGroup
		for range 8 {
			readers.Go(func() {
				got, err := DecodePack(packed)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Error("snapshot differs", err)
				}
				for _, span := range [][2]uint64{{0, uint64(len(dat))}, {0, 0}, {uint64(len(dat)), uint64(len(dat))}, {blocks[1].start - 1, blocks[2].start + 3}, {7, 83}} {
					got, err := ReadPackDAT(packed, span[0], span[1])
					if err != nil || !bytes.Equal(got, dat[span[0]:span[1]]) {
						t.Error("range differs", span, err)
					}
				}
			})
		}
		readers.Wait()
	}
	if !bytes.Equal(input, packed) || packDecodeWorkers.Load() != 0 {
		t.Fatal("input changed or worker leaked")
	}
	// セクションCRCを修復し、各worker内の保存CRC検査まで到達させる。
	for i := range blocks {
		bad := bytes.Clone(packed)
		bad[blocks[i].offset] ^= 1
		repairPackChecksums(bad)
		if got, err := DecodePack(bad); err == nil || got.State != nil {
			t.Fatal("partial or corrupt snapshot returned", i, err)
		}
		if got, err := ReadPackDAT(bad, 0, uint64(len(dat))); err == nil || got != nil {
			t.Fatal("partial or corrupt DAT returned", i, err)
		}
	}
}

// TestVisitPackBlocksWorkers は全要求共通の補助枠と終了待ち・入力順のエラーを検査する。
func TestVisitPackBlocksWorkers(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	blocks := make([]packBlock, 8)
	for i := range blocks {
		blocks[i].chunk.RawLength = 64 << 10
	}
	entered, release := make(chan struct{}, 4), make(chan struct{})
	done := make(chan error, 1)
	first, later := errors.New("first block"), errors.New("later block")
	var visits [8]atomic.Int32
	go func() {
		done <- visitPackBlocks(blocks, func(i int) error {
			if i < 4 {
				entered <- struct{}{}
				<-release
			}
			visits[i].Add(1)
			if i == 0 {
				return first
			}
			return later
		})
	}()
	for range 4 {
		<-entered
	}
	if active := packDecodeWorkers.Load(); active != 3 {
		t.Errorf("helpers=%d, want 3", active)
	}
	// 枠が埋まっていても、別要求は呼出元だけで完了できる。
	if err := visitPackBlocks(blocks, func(int) error { return nil }); err != nil {
		t.Error(err)
	}
	close(release)
	if err := <-done; err != first || packDecodeWorkers.Load() != 0 {
		t.Fatal("error order or worker leak", err)
	}
	for i := range visits {
		if visits[i].Load() != 1 {
			t.Fatal("block not visited exactly once", i)
		}
	}
}

// BenchmarkPackDecode は実際の保存frameとJSON検証を含む全展開・範囲読取りを測る。
func BenchmarkPackDecode(b *testing.B) {
	packed, dat := largePackFixture(b)
	for _, mode := range []string{"snapshot", "dat"} {
		b.Run(mode, func(b *testing.B) {
			cpuBefore, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(dat)))
			b.ReportAllocs()
			for b.Loop() {
				if mode == "snapshot" {
					if _, err := DecodePack(packed); err != nil {
						b.Fatal(err)
					}
				} else if _, err := ReadPackDAT(packed, 0, uint64(len(dat))); err != nil {
					b.Fatal(err)
				}
			}
			cpuAfter, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
		})
	}
}

// BenchmarkPackFramesDecode はJSONを含めず、8frameのzstd展開と両CRC検証を比較する。
func BenchmarkPackFramesDecode(b *testing.B) {
	for _, kind := range []string{"text", "mixed", "entropy"} {
		raw := testutil.DATFixture(kind)
		chunk, err := EncodePackChunk(raw, 6)
		if err != nil {
			b.Fatal(err)
		}
		blocks := make([]packBlock, 8)
		for i := range blocks {
			blocks[i].chunk = chunk
			blocks[i].chunk.Stored = bytes.Clone(chunk.Stored)
		}
		for _, mode := range []string{"serial", "workers"} {
			b.Run(kind+"/"+mode, func(b *testing.B) {
				visit := func(i int) error {
					out, err := DecodePackChunk(blocks[i].chunk)
					if err == nil && len(out) != len(raw) {
						return ErrCorrupt
					}
					return err
				}
				cpuBefore, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(raw) * len(blocks)))
				b.ReportAllocs()
				for b.Loop() {
					if mode == "workers" {
						if err := visitPackBlocks(blocks, visit); err != nil {
							b.Fatal(err)
						}
					} else {
						for i := range blocks {
							if err := visit(i); err != nil {
								b.Fatal(err)
							}
						}
					}
				}
				cpuAfter, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
			})
		}
	}
}
