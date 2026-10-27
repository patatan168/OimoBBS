// WAL圧縮の復号一致、保存上限、破損と不完全末尾の区別、旧世代拒否を検査する。
package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/testutil"
	"strings"
	"testing"
)

func compressionFrames(t *testing.T, count int) ([][]byte, []Frame) {
	t.Helper()
	var raws [][]byte
	var frames []Frame
	for i := 1; i <= count; i++ {
		var id domain.ID
		id[0] = byte(i)
		frame := Frame{FirstSeq: uint64(i), Records: []Record{{ID: id, JSON: []byte(`{"message":"` + strings.Repeat("synthetic signed HTTP log ", 64) + `"}`)}}}
		raw, err := EncodeFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
		frames = append(frames, frame)
	}
	return raws, frames
}

func TestWALCompressedBatchPreservesCanonicalFrames(t *testing.T) {
	raw, want := compressionFrames(t, 64)
	encoded, err := EncodeWALBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= len(bytes.Join(raw, nil))/2 {
		t.Fatal("batch compression ineffective", len(encoded))
	}
	got, n, err := ReadWALBlock(bytes.NewReader(encoded))
	if err != nil || n != int64(len(encoded)) || len(got) != len(want) {
		t.Fatal("batch roundtrip", n, err)
	}
	for i, frame := range got {
		canonical, err := EncodeFrame(frame)
		if err != nil || sha256.Sum256(canonical) != sha256.Sum256(raw[i]) {
			t.Fatal("signed frame identity changed", i, err)
		}
	}
	for cut := 0; cut < len(encoded); cut++ {
		_, _, err := ReadWALBlock(bytes.NewReader(encoded[:cut]))
		if cut == 0 {
			if !errors.Is(err, io.EOF) {
				t.Fatal(cut, err)
			}
		} else if !errors.Is(err, ErrIncomplete) {
			t.Fatal("truncated block was accepted", cut, err)
		}
	}
	for _, at := range []int{0, 4, 8, 12, len(encoded) - 13, len(encoded) - 1} {
		bad := bytes.Clone(encoded)
		bad[at] ^= 1
		if _, _, err := ReadWALBlock(bytes.NewReader(bad)); !errors.Is(err, ErrCorrupt) {
			t.Fatal("corrupt block", at, err)
		}
	}
}

func TestWALNewHeaderRejectsLegacyAndScansCompressedBlocks(t *testing.T) {
	var owner domain.ID
	owner[0] = 1
	h := Header{Owner: owner, Key: 1, Generation: 1}
	header, err := EncodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if string(header[:8]) != "OIMOWAL2" || le.Uint16(header[8:]) != 2 {
		t.Fatal("legacy WAL header still emitted")
	}
	legacy := bytes.Clone(header)
	copy(legacy, "OIMOWAL1")
	le.PutUint16(legacy[8:], 1)
	le.PutUint32(legacy[60:], checksum(legacy[:60]))
	if _, err := DecodeHeader(legacy); !errors.Is(err, ErrCorrupt) {
		t.Fatal("legacy storage accepted", err)
	}
	frames, _ := compressionFrames(t, 2)
	block, err := EncodeWALBlock(frames)
	if err != nil {
		t.Fatal(err)
	}
	file := append(header, block...)
	d := Delta{RequiredSeq: 2, RequiredEnd: domain.U64(len(file)), RequiredSHA: sha256.Sum256(file)}
	seen := 0
	end, incomplete, err := Scan(bytes.NewReader(file), h, d, func(Frame) error { seen++; return nil })
	if err != nil || incomplete || end != int64(len(file)) || seen != 2 {
		t.Fatal(end, incomplete, seen, err)
	}
}

func TestWALBlockRejectsInvalidOrExcessiveFrames(t *testing.T) {
	frames, _ := compressionFrames(t, 1)
	for _, input := range [][][]byte{nil, {[]byte("invalid")}, append(frames, make([][]byte, 64)...)} {
		if _, err := EncodeWALBlock(input); !errors.Is(err, ErrCorrupt) {
			t.Fatal("invalid batch accepted", err)
		}
	}
}

type compressedMemoryFile struct {
	bytes.Buffer
	writes, syncs int
}

func (f *compressedMemoryFile) Write(raw []byte) (int, error) { f.writes++; return f.Buffer.Write(raw) }
func (f *compressedMemoryFile) Sync() error                   { f.syncs++; return nil }

func TestWALWriterUsesCompressedCapacityAndOneSync(t *testing.T) {
	frames, _ := compressionFrames(t, 64)
	file := &compressedMemoryFile{}
	writer := NewWriter(file)
	checked := int64(0)
	r := writer.CommitBatchChecked(frames, func(size int64) error { checked = size; return nil })
	if r.Status != Durable || file.writes != 1 || file.syncs != 1 || checked != int64(file.Len()) || writer.Stats().Bytes != uint64(file.Len()) {
		t.Fatal(r, checked, writer.Stats())
	}
	_, _, err := ReadWALBlock(bytes.NewReader(file.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	before := file.Len()
	r = writer.CommitBatchChecked(frames, func(int64) error { return ErrCorrupt })
	if r.Status != NotWritten || file.Len() != before || file.writes != 1 || file.syncs != 1 {
		t.Fatal("capacity failure wrote bytes", r)
	}
}

// 有効な圧縮blockと長さ偽装を起点に、破損入力でpanicや部分成功が生じないことを確認する。
func FuzzReadWALBlock(f *testing.F) {
	id := domain.ID{1}
	raw, err := EncodeFrame(Frame{FirstSeq: 1, Records: []Record{{ID: id, JSON: []byte(`{"message":"` + strings.Repeat("synthetic log ", 128) + `"}`)}}})
	if err != nil {
		f.Fatal(err)
	}
	second, err := EncodeFrame(Frame{FirstSeq: 2, Records: []Record{{ID: domain.ID{2}, JSON: []byte(`{"message":"` + strings.Repeat("synthetic log ", 128) + `"}`)}}})
	if err != nil {
		f.Fatal(err)
	}
	block, err := EncodeWALBlock([][]byte{raw, second})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(block)
	f.Add(raw)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{255}, 8))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > maxWALRaw+20 {
			t.Skip()
		}
		frames, n, err := ReadWALBlock(bytes.NewReader(input))
		if n < 0 || n > int64(len(input)) {
			t.Fatal("invalid consumed length", n)
		}
		if err != nil {
			if len(frames) != 0 {
				t.Fatal("partial output returned")
			}
			return
		}
		if len(frames) == 0 || len(frames) > MaxCommitFrames {
			t.Fatal("frame count")
		}
		for _, frame := range frames {
			if _, err := EncodeFrame(frame); err != nil {
				t.Fatal("invalid decoded frame", err)
			}
		}
	})
}

// 単一frameの最大長でも1MiB窓のZstandardを独立decoderで展開できることを検証する。
func TestWALMaximumFrameRoundTrip(t *testing.T) {
	frame := Frame{FirstSeq: 1}
	remaining := MaxFrameBody - 12 - 4*(24+2)
	for i := 0; i < 4; i++ {
		size := remaining / (4 - i)
		remaining -= size
		frame.Records = append(frame.Records, Record{ID: domain.ID{byte(i + 1)}, JSON: []byte(`{}`), DAT: bytes.Repeat([]byte{byte(65 + i)}, size)})
	}
	raw, err := EncodeFrame(frame)
	if err != nil || len(raw) != maxWALRaw {
		t.Fatal("maximum canonical size", len(raw), err)
	}
	block, err := EncodeWALBlock([][]byte{raw})
	if err != nil || le.Uint32(block)&walCompressedFlag == 0 {
		t.Fatal("maximum compression", err)
	}
	independent, err := testutil.DecodeZstd(block[16 : len(block)-12])
	if err != nil || !bytes.Equal(independent, raw) {
		t.Fatal("independent maximum decode", err)
	}
	frames, n, err := ReadWALBlock(bytes.NewReader(block))
	if err != nil || n != int64(len(block)) || len(frames) != 1 {
		t.Fatal(n, err)
	}
	got, err := EncodeFrame(frames[0])
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("maximum canonical bytes changed", err)
	}
}

func TestWALSmallRawFallback(t *testing.T) {
	raw, err := EncodeFrame(Frame{FirstSeq: 1, Records: []Record{{ID: domain.ID{1}, JSON: []byte(`{}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	block, err := EncodeWALBlock([][]byte{raw})
	if err != nil || !bytes.Equal(block, raw) {
		t.Fatal("small frame grew", len(block), len(raw), err)
	}
	frames, n, err := ReadWALBlock(bytes.NewReader(block))
	if err != nil || n != int64(len(raw)) || len(frames) != 1 {
		t.Fatal(n, err)
	}
}

// 圧縮可能でも小さい単独Syncはrawを維持し、既に到着したbatchだけをまとめて圧縮する。
func TestWALSmallSingleSyncStaysRaw(t *testing.T) {
	raw, err := EncodeFrame(Frame{FirstSeq: 1, Records: []Record{{ID: domain.ID{1}, JSON: []byte(`{"message":"` + strings.Repeat("critical posting record ", 400) + `"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) >= minSingleWALCompression {
		t.Fatal("fixture exceeds small-frame threshold")
	}
	single, err := EncodeWALBlock([][]byte{raw})
	if err != nil || !bytes.Equal(single, raw) {
		t.Fatal("small critical Sync changed bytes", err)
	}
	batch, err := EncodeWALBlock([][]byte{raw, raw})
	if err != nil || len(batch) >= len(raw) || le.Uint32(batch)&walCompressedFlag == 0 {
		t.Fatal("arrived batch was not compressed", err)
	}
	frames, _, err := ReadWALBlock(bytes.NewReader(batch))
	if err != nil || len(frames) != 2 {
		t.Fatal("batch roundtrip", err)
	}
}
