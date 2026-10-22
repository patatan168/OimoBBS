// 保存用復号を独立decoderと照合し、サイズ制限・破損・末尾ごみを検証する。
package zstddecode

import (
	"bytes"
	"math/rand"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstdencode"
	"testing"
)

func TestOwnFrames(t *testing.T) {
	random := make([]byte, 512<<10)
	rand.New(rand.NewSource(71)).Read(random)
	samples := [][]byte{nil, {1}, bytes.Repeat([]byte{7}, 200000), random, testutil.DATFixture("text"), testutil.DATFixture("entropy"), testutil.DATFixture("mixed")}
	for _, n := range []int{255, 256, 65791, 65792, 131072, 131073, 524288} {
		samples = append(samples, bytes.Repeat([]byte("abcd"), (n+3)/4)[:n])
	}
	var encoder zstdencode.Encoder
	for _, raw := range samples {
		frame := encoder.Encode(raw)
		expected, err := testutil.DecodeZstd(frame)
		if err != nil || !bytes.Equal(expected, raw) {
			t.Fatal("independent", err)
		}
		got, err := Decode(frame, len(raw))
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatalf("size %d: %v", len(raw), err)
		}
		if len(raw) > 0 {
			if _, err = Decode(frame, len(raw)-1); err == nil {
				t.Fatal("size mismatch")
			}
		}
		for _, bad := range [][]byte{frame[:len(frame)-1], append(bytes.Clone(frame), 0), append(bytes.Clone(frame), frame...)} {
			if _, err = Decode(bad, len(raw)); err == nil {
				t.Fatal("truncated/trailing accepted")
			}
		}
	}
}

func FuzzDecode(f *testing.F) {
	var encoder zstdencode.Encoder
	for _, raw := range [][]byte{nil, []byte("hello"), testutil.DATFixture("mixed")[:16384], bytes.Repeat([]byte{9}, 2000)} {
		f.Add(encoder.Encode(raw), uint32(len(raw)))
	}
	f.Fuzz(func(t *testing.T, frame []byte, size uint32) {
		if len(frame) > 600000 {
			t.Skip()
		}
		got, err := Decode(frame, int(size))
		if err != nil {
			return
		}
		expected, err := testutil.DecodeZstd(frame)
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatal("accepted different bytes", err)
		}
	})
}

// TestArchiveProfiles は保存探索・表精度の全組合せと配信用出力の維持を照合する。
func TestArchiveProfiles(t *testing.T) {
	for _, raw := range [][]byte{testutil.DATFixture("entropy"), testutil.DATFixture("mixed"), testutil.DATFixture("text"), bytes.Repeat([]byte{255, 0, 7}, 2000)} {
		var encoder, fast zstdencode.Encoder
		expectedFast := fast.Encode(raw)
		for _, hash := range []int{0, 4, 5, 6, 7} {
			for _, log := range []uint{7, 8, 9} {
				frame, err := encoder.EncodeArchive(raw, zstdencode.ArchiveOptions{HashBytes: hash, AccuracyLog: log})
				if err != nil {
					t.Fatal(err)
				}
				expected, err := testutil.DecodeZstd(frame)
				if err != nil || !bytes.Equal(expected, raw) {
					t.Fatal("independent archive", err)
				}
				got, err := Decode(frame, len(raw))
				if err != nil || !bytes.Equal(got, expected) {
					t.Fatal("archive decode", err)
				}
			}
		}
		if !bytes.Equal(encoder.Encode(raw), expectedFast) {
			t.Fatal("public encoding changed")
		}
	}
}

func FuzzArchiveRoundTrip(f *testing.F) {
	f.Add([]byte("archive body"), byte(0), byte(0))
	f.Add(bytes.Repeat([]byte{255, 0, 97}, 2048), byte(3), byte(2))
	f.Fuzz(func(t *testing.T, raw []byte, hash, accuracy byte) {
		if len(raw) > 32768 {
			t.Skip()
		}
		width := int(hash % 5)
		if width > 0 {
			width += 3
		}
		var encoder zstdencode.Encoder
		frame, err := encoder.EncodeArchive(raw, zstdencode.ArchiveOptions{HashBytes: width, AccuracyLog: uint(accuracy%3) + 7})
		if err != nil {
			t.Fatal(err)
		}
		independent, err := testutil.DecodeZstd(frame)
		if err != nil || !bytes.Equal(independent, raw) {
			t.Fatal("archive independent", err)
		}
		got, err := Decode(frame, len(raw))
		if err != nil || !bytes.Equal(got, independent) {
			t.Fatal("archive roundtrip", err)
		}
	})
}
