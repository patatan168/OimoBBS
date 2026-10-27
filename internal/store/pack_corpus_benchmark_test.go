// 日本語・混合・高エントロピーの合成DATで、pack全復元と読取りのCPU・割当を比較する。
package store

import (
	"bytes"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/testutil"
	"oimobbs/internal/textcodec"
)

// corpusPackFixture は同じ1000レスDATから意味検証可能なpackを作る。稼働データは使わない。
func corpusPackFixture(t testing.TB, kind string) ([]byte, []byte) {
	t.Helper()
	s, err := DecodePack(packFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if kind == "small" {
		return packFixture(t), bytes.Join(s.State.Lines, nil)
	}
	dat := testutil.DATFixture(kind)
	lines := bytes.SplitAfter(dat, []byte{'\n'})
	lines = lines[:len(lines)-1]
	post := s.State.Posts[1]
	s.State.Posts = make([]domain.Post, len(lines))
	s.State.Lines = lines
	s.Origins = make([]domain.U64, len(lines))
	s.Dedup, s.Audit = nil, nil
	var offset uint32
	for i, line := range lines {
		p := post
		p.Number = uint32(i + 1)
		if i == 0 {
			p.Created = s.State.Created
		}
		fields := bytes.SplitN(line, []byte("<>"), 5)
		p.Body, err = textcodec.Decode(fields[3])
		if err != nil {
			t.Fatal(err)
		}
		p.DATOffset, p.DATLength = offset, uint32(len(line))
		offset += p.DATLength
		s.State.Posts[i] = p
		s.Origins[i] = s.State.Revision
	}
	s.State.After.PostCount = uint32(len(lines))
	s.State.After.UserCount = uint32(len(lines))
	s.State.After.DATBytes = domain.U64(offset)
	s.State.After.LastUserAt = s.State.Posts[len(lines)-1].Created
	packed, err := EncodePack(s, 6)
	if err != nil {
		t.Fatal(err)
	}
	return packed, dat
}

func BenchmarkPackDecodeCorpus(b *testing.B) {
	for _, kind := range []string{"small", "text", "mixed", "entropy"} {
		packed, dat := corpusPackFixture(b, kind)
		for _, mode := range []string{"snapshot", "dat"} {
			b.Run(kind+"/"+mode, func(b *testing.B) {
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
}
