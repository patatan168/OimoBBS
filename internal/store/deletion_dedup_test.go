// 再送拒否entryの期限・所有位置・固定長領域を破損入力から検証する。
package store

import (
	"bytes"
	"math"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

func TestRejectedDedupCodec(t *testing.T) {
	for _, mode := range []string{"explicit", "implicit"} {
		t.Run(mode, func(t *testing.T) {
			d := PackDedup{ID: domain.ID{1}, Seq: 7, Committed: 1700000000e9, Value: domain.Dedup{Mode: mode, KeyID: 8, Subject: domain.Hash{2}, Request: domain.Hash{3}, PostNumber: 5}}
			duration := domain.Time(30 * time.Second)
			if mode == "explicit" {
				duration = domain.Time(24 * time.Hour)
				h := domain.Hash{4}
				d.Value.RequestID = &h
			}
			d.Value.Expires = d.Committed + duration
			x, e := EncodeRejectedDedup(d, 9, d.Committed)
			if e != nil || len(x) != 160 || x[1] != 2 {
				t.Fatal(len(x), e)
			}
			decoded, e := DecodeRejectedDedup(x, 9, d.Value.Expires-1)
			if e != nil || !reflect.DeepEqual(decoded, d) {
				t.Fatal(decoded, e)
			}
			for i := range x {
				bad := bytes.Clone(x)
				bad[i] ^= 1
				if _, e = DecodeRejectedDedup(bad, 9, d.Committed); e == nil {
					t.Fatalf("byte %d corruption accepted", i)
				}
			}
			for _, offset := range []int{0, 1, 2, 3, 132, 135, 152, 155} {
				bad := bytes.Clone(x)
				bad[offset] = 3
				le.PutUint32(bad[156:], checksum(bad[:156]))
				if _, e = DecodeRejectedDedup(bad, 9, d.Committed); e == nil {
					t.Fatalf("reserved/tag offset %d accepted", offset)
				}
			}
			for _, length := range []int{0, 159, 161} {
				bad := make([]byte, length)
				copy(bad, x)
				if _, e = DecodeRejectedDedup(bad, 9, d.Committed); e == nil {
					t.Fatalf("length %d accepted", length)
				}
			}
			for _, boundary := range []struct {
				seq domain.U64
				now domain.Time
			}{{6, d.Committed}, {9, d.Value.Expires}} {
				if _, e = DecodeRejectedDedup(x, boundary.seq, boundary.now); e == nil {
					t.Fatal("invalid source/expiry accepted", boundary)
				}
			}
			for _, change := range []func(*PackDedup){
				func(d *PackDedup) { d.ID = domain.ID{} },
				func(d *PackDedup) { d.Seq = 0 },
				func(d *PackDedup) { d.Value.KeyID = 0 },
				func(d *PackDedup) { d.Value.PostNumber = 0 },
				func(d *PackDedup) { d.Value.Expires++ },
				func(d *PackDedup) { d.Committed = 0 },
				func(d *PackDedup) { d.Committed = math.MaxInt64; d.Value.Expires = 1 },
				func(d *PackDedup) { d.Value.Mode = "other" },
			} {
				bad := d
				change(&bad)
				if _, e = EncodeRejectedDedup(bad, 9, d.Committed); e == nil {
					t.Fatal("invalid metadata accepted", bad)
				}
			}
		})
	}
}

func TestRejectedDedupMatchesPackFixture(t *testing.T) {
	s, e := DecodePack(packFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	section, e := encodePackDedup(s)
	if e != nil {
		t.Fatal(e)
	}
	for i := 32; i < len(section); i += 160 {
		accepted := section[i : i+160]
		d, e := decodeDedupEntry(accepted, 1)
		if e != nil {
			t.Fatal(e)
		}
		rejected, e := EncodeRejectedDedup(d, s.State.Revision, s.At)
		if e != nil {
			t.Fatal(e)
		}
		want := bytes.Clone(accepted)
		want[1] = 2
		le.PutUint32(want[156:], checksum(want[:156]))
		if !bytes.Equal(rejected, want) {
			t.Fatal("carry changed fixture layout")
		}
		if _, e = DecodeRejectedDedup(accepted, s.State.Revision, s.At); e == nil {
			t.Fatal("accepted entry interpreted as rejection")
		}
		badSection := bytes.Clone(section)
		copy(badSection[i:], rejected)
		if _, e = decodePackDedup(badSection, s); e == nil {
			t.Fatal("rejection interpreted as accepted pack index")
		}
	}
}
