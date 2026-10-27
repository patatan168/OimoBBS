// 未満了の投稿再送索引を設計11の固定長形式へ変換する。
package store

import (
	"bytes"
	"math"
	"oimobbs/internal/domain"
	"sort"
	"time"
)

func dedupLookup(d domain.Dedup) domain.Hash {
	if d.RequestID != nil {
		return *d.RequestID
	}
	return d.Request
}
func comparePackDedup(a, b PackDedup) int {
	if a.Value.KeyID < b.Value.KeyID {
		return -1
	}
	if a.Value.KeyID > b.Value.KeyID {
		return 1
	}
	if a.Value.Mode != b.Value.Mode {
		if a.Value.Mode == "explicit" {
			return -1
		}
		return 1
	}
	if n := bytes.Compare(a.Value.Subject[:], b.Value.Subject[:]); n != 0 {
		return n
	}
	x, y := dedupLookup(a.Value), dedupLookup(b.Value)
	return bytes.Compare(x[:], y[:])
}
func validatePackDedup(d PackDedup, s PackSnapshot) error {
	v := d.Value
	duration := int64(30 * time.Second)
	if v.Mode == "explicit" {
		duration = int64(24 * time.Hour)
		if v.RequestID == nil {
			return ErrCorrupt
		}
	} else if v.Mode != "implicit" || v.RequestID != nil {
		return ErrCorrupt
	}
	if d.ID == (domain.ID{}) || d.Seq == 0 || d.Seq > s.State.Revision || v.KeyID == 0 || v.PostNumber == 0 || v.PostNumber > s.State.After.PostCount || int64(d.Committed) > math.MaxInt64-duration || v.Expires != d.Committed+domain.Time(duration) || v.Expires <= s.At {
		return ErrCorrupt
	}
	p := s.State.Posts[v.PostNumber-1]
	if p.Kind != "user" || p.Created != d.Committed || s.Origins[v.PostNumber-1] != d.Seq {
		return ErrCorrupt
	}
	return nil
}
func encodePackDedup(s PackSnapshot) ([]byte, error) {
	entries := append([]PackDedup{}, s.Dedup...)
	sort.Slice(entries, func(i, j int) bool { return comparePackDedup(entries[i], entries[j]) < 0 })
	if len(entries) > MaxPackEntries {
		return nil, ErrCorrupt
	}
	b := make([]byte, 32+160*len(entries))
	copy(b, "OIMODED1")
	le.PutUint16(b[8:], 1)
	le.PutUint16(b[10:], 32)
	le.PutUint32(b[12:], uint32(len(entries)))
	le.PutUint64(b[16:], uint64(s.State.Revision))
	le.PutUint16(b[24:], 160)
	le.PutUint32(b[28:], checksum(b[:28]))
	seen := map[domain.ID]bool{}
	for i, d := range entries {
		if e := validatePackDedup(d, s); e != nil {
			return nil, e
		}
		if seen[d.ID] || i > 0 && comparePackDedup(entries[i-1], d) >= 0 {
			return nil, ErrCorrupt
		}
		seen[d.ID] = true
		copy(b[32+i*160:], encodeDedupEntry(d, 1))
	}
	return b, nil
}
func decodePackDedup(b []byte, s PackSnapshot) ([]PackDedup, error) {
	if len(b) < 32 || string(b[:8]) != "OIMODED1" || le.Uint16(b[8:]) != 1 || le.Uint16(b[10:]) != 32 || le.Uint64(b[16:]) != uint64(s.State.Revision) || le.Uint16(b[24:]) != 160 || le.Uint16(b[26:]) != 0 || le.Uint32(b[28:]) != checksum(b[:28]) {
		return nil, ErrCorrupt
	}
	n := uint64(le.Uint32(b[12:]))
	if n > MaxPackEntries || 32+160*n != uint64(len(b)) {
		return nil, ErrCorrupt
	}
	out := make([]PackDedup, 0, int(n))
	seen := map[domain.ID]bool{}
	for i := uint64(0); i < n; i++ {
		x := b[32+i*160 : 32+(i+1)*160]
		d, e := decodeDedupEntry(x, 1)
		if e != nil {
			return nil, e
		}
		if e := validatePackDedup(d, s); e != nil {
			return nil, e
		}
		if seen[d.ID] || len(out) > 0 && comparePackDedup(out[len(out)-1], d) >= 0 {
			return nil, ErrCorrupt
		}
		seen[d.ID] = true
		out = append(out, d)
	}
	return out, nil
}

// encodeDedupEntry は検証済み索引を、accepted/rejected共通の固定長形式へ変換する。
func encodeDedupEntry(d PackDedup, result byte) []byte {
	x := make([]byte, 160)
	v := d.Value
	x[0], x[1] = 2, result
	if v.Mode == "explicit" {
		x[0] = 1
		copy(x[40:72], v.RequestID[:])
	}
	le.PutUint32(x[4:8], v.KeyID)
	copy(x[8:40], v.Subject[:])
	copy(x[72:104], v.Request[:])
	copy(x[104:120], d.ID[:])
	le.PutUint64(x[120:128], uint64(d.Seq))
	le.PutUint32(x[128:132], v.PostNumber)
	le.PutUint64(x[136:144], uint64(d.Committed))
	le.PutUint64(x[144:152], uint64(v.Expires))
	le.PutUint32(x[156:160], checksum(x[:156]))
	return x
}

// decodeDedupEntry は用途別resultと予約領域を照合する。期限等は呼出元が検証する。
func decodeDedupEntry(x []byte, result byte) (PackDedup, error) {
	if len(x) != 160 || (x[0] != 1 && x[0] != 2) || x[1] != result || le.Uint16(x[2:4]) != 0 || le.Uint32(x[132:136]) != 0 || le.Uint32(x[152:156]) != 0 || le.Uint32(x[156:160]) != checksum(x[:156]) {
		return PackDedup{}, ErrCorrupt
	}
	d := PackDedup{Seq: domain.U64(le.Uint64(x[120:128])), Committed: domain.Time(le.Uint64(x[136:144]))}
	copy(d.ID[:], x[104:120])
	v := &d.Value
	v.Mode, v.KeyID = "implicit", le.Uint32(x[4:8])
	copy(v.Subject[:], x[8:40])
	copy(v.Request[:], x[72:104])
	v.PostNumber, v.Expires = le.Uint32(x[128:132]), domain.Time(le.Uint64(x[144:152]))
	var request domain.Hash
	copy(request[:], x[40:72])
	if x[0] == 1 {
		v.Mode, v.RequestID = "explicit", &request
	} else if request != (domain.Hash{}) {
		return PackDedup{}, ErrCorrupt
	}
	return d, nil
}
