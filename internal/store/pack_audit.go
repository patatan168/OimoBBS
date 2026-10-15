// packの操作要約を有界chunkへ分割し、順序・保持期限・対象範囲を検査する。
package store

import (
	"encoding/json"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"slices"
	"time"
)

const packAuditRetention = domain.Time(180 * 24 * time.Hour)

func validatePackAudit(a PackAudit, s PackSnapshot) error {
	if a.ID == (domain.ID{}) || a.Seq == 0 || a.Seq > s.State.Revision || a.Actor.Validate() != nil || a.Versions.Site == 0 || a.Versions.Board == 0 || a.Ranges == nil || len(a.Ranges) > 256 || int64(a.Committed) > math.MaxInt64-int64(packAuditRetention) || a.Expires != a.Committed+packAuditRetention || a.Expires <= s.At {
		return ErrCorrupt
	}
	if !slices.Contains([]string{"create", "append", "redact", "stop", "archive", "move_link", "hide", "update_policy"}, a.Type) {
		return ErrCorrupt
	}
	if a.Type == "create" {
		if a.Seq != 1 || a.Versions.Thread != 0 {
			return ErrCorrupt
		}
	} else if a.Versions.Thread == 0 {
		return ErrCorrupt
	}
	if (a.Type == "create" || a.Type == "append") && (a.Actor.Kind != "anonymous" && a.Actor.Kind != "cap") {
		return ErrCorrupt
	}
	var prev uint32
	for _, r := range a.Ranges {
		if r.First == 0 || r.First > r.Last || r.First <= prev || r.Last > s.State.After.PostCount {
			return ErrCorrupt
		}
		prev = r.Last
	}
	modifies := slices.Contains([]string{"create", "append", "redact", "stop"}, a.Type)
	if modifies != (len(a.Ranges) > 0) {
		return ErrCorrupt
	}
	return nil
}
func encodePackAudit(s PackSnapshot, level uint8) ([]byte, error) {
	if len(s.Audit) > MaxPackEntries {
		return nil, ErrCorrupt
	}
	b := make([]byte, 32)
	copy(b, "OIMOAUD1")
	le.PutUint16(b[8:], 1)
	le.PutUint16(b[10:], 32)
	le.PutUint32(b[12:], uint32(len(s.Audit)))
	le.PutUint64(b[16:], uint64(s.State.Revision))
	var raw []byte
	var count, chunks uint32
	var prev domain.U64
	seen := map[domain.ID]bool{}
	flush := func() error {
		c, e := EncodePackChunk(raw, level)
		if e != nil {
			return e
		}
		h := make([]byte, 24)
		le.PutUint32(h, count)
		le.PutUint32(h[4:], c.RawLength)
		le.PutUint32(h[8:], uint32(len(c.Stored)))
		h[12] = c.Codec
		h[13] = c.Level
		le.PutUint32(h[16:], c.RawCRC)
		le.PutUint32(h[20:], c.StoredCRC)
		b = append(b, h...)
		b = append(b, c.Stored...)
		raw = nil
		count = 0
		chunks++
		return nil
	}
	total := 0
	for _, a := range s.Audit {
		if e := validatePackAudit(a, s); e != nil {
			return nil, e
		}
		if a.Seq <= prev || seen[a.ID] {
			return nil, ErrCorrupt
		}
		prev = a.Seq
		seen[a.ID] = true
		j, e := json.Marshal(a)
		if e != nil {
			return nil, e
		}
		if len(j) > 65536 {
			return nil, ErrCorrupt
		}
		total += len(j) + 8
		if total > MaxPackFile {
			return nil, ErrCorrupt
		}
		if len(raw)+len(j)+8 > MaxPackRaw {
			if e = flush(); e != nil {
				return nil, e
			}
		}
		entry := make([]byte, len(j)+8)
		le.PutUint32(entry, uint32(len(j)))
		copy(entry[4:], j)
		le.PutUint32(entry[4+len(j):], checksum(j))
		raw = append(raw, entry...)
		count++
	}
	if count > 0 {
		if e := flush(); e != nil {
			return nil, e
		}
	}
	le.PutUint32(b[24:], chunks)
	le.PutUint32(b[28:], checksum(b[:28]))
	return b, nil
}
func decodePackAudit(b []byte, s PackSnapshot, budget *int) ([]PackAudit, error) {
	if len(b) < 32 || string(b[:8]) != "OIMOAUD1" || le.Uint16(b[8:]) != 1 || le.Uint16(b[10:]) != 32 || le.Uint64(b[16:]) != uint64(s.State.Revision) || le.Uint32(b[28:]) != checksum(b[:28]) {
		return nil, ErrCorrupt
	}
	count, chunks := le.Uint32(b[12:]), le.Uint32(b[24:])
	if count > MaxPackEntries || chunks > count || (count == 0) != (chunks == 0) {
		return nil, ErrCorrupt
	}
	out := []PackAudit{}
	pos := 32
	seen := map[domain.ID]bool{}
	var prev domain.U64
	for i := uint32(0); i < chunks; i++ {
		if len(b)-pos < 24 {
			return nil, ErrCorrupt
		}
		h := b[pos : pos+24]
		pos += 24
		n, stored, rawLen := le.Uint32(h), le.Uint32(h[8:]), le.Uint32(h[4:])
		if n == 0 || uint64(len(out))+uint64(n) > uint64(count) || uint64(stored) > uint64(len(b)-pos) || le.Uint16(h[14:]) != 0 || uint64(rawLen) > uint64(*budget) {
			return nil, ErrCorrupt
		}
		*budget -= int(rawLen)
		raw, e := DecodePackChunk(PackChunk{h[12], h[13], rawLen, le.Uint32(h[16:]), le.Uint32(h[20:]), b[pos : pos+int(stored)]})
		if e != nil {
			return nil, e
		}
		pos += int(stored)
		rp := 0
		for k := uint32(0); k < n; k++ {
			if len(raw)-rp < 8 {
				return nil, ErrCorrupt
			}
			size := uint64(le.Uint32(raw[rp:]))
			rp += 4
			if size < 2 || size > 65536 || size > uint64(len(raw)-rp-4) {
				return nil, ErrCorrupt
			}
			j := raw[rp : rp+int(size)]
			rp += int(size)
			if le.Uint32(raw[rp:]) != checksum(j) {
				return nil, ErrCorrupt
			}
			rp += 4
			var a PackAudit
			if e = strictjson.Decode(j, &a); e != nil {
				return nil, e
			}
			if e = validatePackAudit(a, s); e != nil {
				return nil, e
			}
			if a.Seq <= prev || seen[a.ID] {
				return nil, ErrCorrupt
			}
			prev = a.Seq
			seen[a.ID] = true
			out = append(out, a)
		}
		if rp != len(raw) {
			return nil, ErrCorrupt
		}
	}
	if pos != len(b) || uint32(len(out)) != count {
		return nil, ErrCorrupt
	}
	return out, nil
}
