// pack本文ブロックの区切り・索引・JSON/DATの相互照合を行う。
package store

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

// packPostRecord はDAT offsetをブロック基準に正規化して符号化する。
func packPostRecord(post domain.Post, line []byte, seq domain.U64, offset uint32) ([]byte, error) {
	post.DATOffset = offset
	b, e := json.Marshal(post)
	if e != nil {
		return nil, e
	}
	if len(b)+len(line)+32 > MaxPackRaw {
		return nil, ErrCorrupt
	}
	var checked domain.Post
	if e = strictjson.Decode(b, &checked); e != nil {
		return nil, e
	}
	raw := make([]byte, 16+len(b)+len(line))
	le.PutUint64(raw, uint64(seq))
	le.PutUint32(raw[8:], uint32(len(b)))
	copy(raw[12:], b)
	at := 12 + len(b)
	le.PutUint32(raw[at:], uint32(len(line)))
	copy(raw[at+4:], line)
	return raw, nil
}

func buildPackBlocks(s PackSnapshot, level uint8) ([]packBlock, error) {
	var blocks []packBlock
	raw := make([]byte, 16)
	copy(raw, "OIMOBLK1")
	var current packBlock
	totalRaw := 0
	finish := func() error {
		le.PutUint32(raw[8:], current.count)
		totalRaw += len(raw)
		if totalRaw > MaxPackFile {
			return ErrCorrupt
		}
		c, e := EncodePackChunk(raw, level)
		if e != nil {
			return e
		}
		current.chunk = c
		blocks = append(blocks, current)
		start := current.start + current.length
		current = packBlock{start: start}
		raw = make([]byte, 16)
		copy(raw, "OIMOBLK1")
		return nil
	}
	for i, p := range s.State.Posts {
		line := s.State.Lines[i]
		seq := s.Origins[i]
		rec, e := packPostRecord(p, line, seq, uint32(current.length))
		if current.count > 0 && (e != nil || current.length+uint64(len(line)) > packDATTarget || len(raw)+len(rec) > MaxPackRaw) {
			if e = finish(); e != nil {
				return nil, e
			}
			rec, e = packPostRecord(p, line, seq, 0)
			if e != nil {
				return nil, e
			}
		}
		if e != nil {
			return nil, e
		}
		if current.count == 0 {
			current.first = p.Number
		}
		current.observe(p, seq, len(line))
		raw = append(raw, rec...)
	}
	if current.count > 0 {
		if e := finish(); e != nil {
			return nil, e
		}
	}
	return blocks, nil
}

func (b *packBlock) observe(p domain.Post, seq domain.U64, size int) {
	if b.count == 0 {
		b.minSeq = seq
		b.maxSeq = seq
	}
	b.count++
	b.length += uint64(size)
	b.minSeq = min(b.minSeq, seq)
	b.maxSeq = max(b.maxSeq, seq)
	if p.Kind == "user" {
		if b.users == 0 {
			b.minTime = p.Created
			b.maxTime = p.Created
		}
		b.users++
		b.minTime = min(b.minTime, p.Created)
		b.maxTime = max(b.maxTime, p.Created)
	}
}

func (b packBlock) index() []byte {
	x := make([]byte, 96)
	le.PutUint32(x, b.first)
	le.PutUint32(x[4:], b.count)
	le.PutUint64(x[8:], b.start)
	le.PutUint64(x[16:], b.length)
	le.PutUint64(x[24:], b.offset)
	le.PutUint32(x[32:], uint32(len(b.chunk.Stored)))
	le.PutUint32(x[36:], b.chunk.RawLength)
	x[40] = b.chunk.Codec
	x[41] = b.chunk.Level
	le.PutUint32(x[44:], b.chunk.StoredCRC)
	le.PutUint32(x[48:], b.chunk.RawCRC)
	le.PutUint32(x[52:], b.users)
	le.PutUint64(x[56:], uint64(b.minTime))
	le.PutUint64(x[64:], uint64(b.maxTime))
	le.PutUint64(x[72:], uint64(b.minSeq))
	le.PutUint64(x[80:], uint64(b.maxSeq))
	le.PutUint32(x[92:], checksum(x[:92]))
	return x
}

func decodePackBlock(b packBlock, base domain.U64) ([]domain.Post, [][]byte, []domain.U64, error) {
	raw, e := DecodePackChunk(b.chunk)
	if e != nil {
		return nil, nil, nil, e
	}
	if len(raw) < 16 || string(raw[:8]) != "OIMOBLK1" || le.Uint32(raw[8:]) != b.count || le.Uint32(raw[12:]) != 0 || uint64(b.count) > uint64(len(raw)-16)/18 {
		return nil, nil, nil, ErrCorrupt
	}
	var posts []domain.Post
	var lines [][]byte
	var origins []domain.U64
	actual := packBlock{first: b.first, start: b.start}
	pos := 16
	for i := uint32(0); i < b.count; i++ {
		if len(raw)-pos < 12 {
			return nil, nil, nil, ErrCorrupt
		}
		seq := domain.U64(le.Uint64(raw[pos:]))
		n := uint64(le.Uint32(raw[pos+8:]))
		pos += 12
		if seq == 0 || seq > base || n < 2 || n > uint64(len(raw)-pos) {
			return nil, nil, nil, ErrCorrupt
		}
		var p domain.Post
		if e = strictjson.Decode(raw[pos:pos+int(n)], &p); e != nil {
			return nil, nil, nil, e
		}
		pos += int(n)
		if len(raw)-pos < 4 {
			return nil, nil, nil, ErrCorrupt
		}
		dn := uint64(le.Uint32(raw[pos:]))
		pos += 4
		if dn > uint64(len(raw)-pos) || dn != uint64(p.DATLength) || p.Number != b.first+i || uint64(p.DATOffset) != actual.length {
			return nil, nil, nil, ErrCorrupt
		}
		line := bytes.Clone(raw[pos : pos+int(dn)])
		pos += int(dn)
		if e = domain.ValidateStoredPost(p, line); e != nil {
			return nil, nil, nil, e
		}
		actual.observe(p, seq, len(line))
		posts = append(posts, p)
		lines = append(lines, line)
		origins = append(origins, seq)
	}
	if pos != len(raw) || actual.length != b.length || actual.users != b.users || actual.minTime != b.minTime || actual.maxTime != b.maxTime || actual.minSeq != b.minSeq || actual.maxSeq != b.maxSeq {
		return nil, nil, nil, ErrCorrupt
	}
	return posts, lines, origins, nil
}
