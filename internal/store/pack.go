// 設計12のpack v1を符号化・復号し、全セクションと現在値を照合する。
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

// EncodePack は現在値をレス単位のブロックへ分割し、v1の全5セクションを生成する。
// hidden・基準時刻で期限切れ・資源上限超過の候補は生成しない。
func EncodePack(s PackSnapshot, level uint8) ([]byte, error) {
	if s.Owner == (domain.ID{}) || s.Key == 0 || s.Generation == 0 || s.State == nil || s.At >= s.State.Expires || !packLevel(level) || len(s.Origins) != len(s.State.Posts) {
		return nil, ErrCorrupt
	}
	if e := domain.ValidateSnapshot(s.State); e != nil {
		return nil, e
	}
	for _, seq := range s.Origins {
		if seq == 0 || seq > s.State.Revision {
			return nil, ErrCorrupt
		}
	}
	meta := packMetadata{Title: s.State.Title, Created: s.State.Created, Expires: s.State.Expires, Revision: s.State.Revision, After: s.State.After, Policy: s.State.Policy, LastOperation: s.LastOperation}
	if s.State.MoveTarget != "" {
		v := s.State.MoveTarget
		meta.Move = &v
	}
	hash := sha256.New()
	for _, line := range s.State.Lines {
		_, _ = hash.Write(line)
	}
	copy(meta.DATHash[:], hash.Sum(nil))
	m, e := json.Marshal(meta)
	if e != nil {
		return nil, e
	}
	if len(m) > 1<<20 {
		return nil, ErrCorrupt
	}
	var checked packMetadata
	if e = strictjson.Decode(m, &checked); e != nil {
		return nil, e
	}
	blocks, e := buildPackBlocks(s, level)
	if e != nil {
		return nil, e
	}
	dedup, e := encodePackDedup(s)
	if e != nil {
		return nil, e
	}
	audit, e := encodePackAudit(s, level)
	if e != nil {
		return nil, e
	}
	offset := uint64(256 + len(m) + 96*len(blocks) + len(dedup) + len(audit))
	var index, stored []byte
	budget := 0
	for _, b := range blocks {
		budget += int(b.chunk.RawLength)
		if budget > MaxPackFile || offset+uint64(len(b.chunk.Stored)) > MaxPackFile {
			return nil, ErrCorrupt
		}
		b.offset = offset
		index = append(index, b.index()...)
		stored = append(stored, b.chunk.Stored...)
		offset += uint64(len(b.chunk.Stored))
	}
	header := make([]byte, 256)
	copy(header, "OIMOPAK1")
	le.PutUint16(header[8:], 1)
	le.PutUint16(header[10:], 256)
	copy(header[16:], s.Owner[:])
	le.PutUint64(header[32:], s.Key)
	le.PutUint64(header[40:], s.Generation)
	le.PutUint64(header[48:], uint64(s.State.Revision))
	le.PutUint64(header[56:], uint64(s.State.After.DATGeneration))
	le.PutUint64(header[64:], uint64(s.State.Created))
	le.PutUint64(header[72:], uint64(s.State.Expires))
	le.PutUint32(header[80:], s.State.After.PostCount)
	le.PutUint32(header[84:], uint32(len(blocks)))
	le.PutUint64(header[88:], uint64(s.State.After.DATBytes))
	le.PutUint64(header[216:], offset)
	le.PutUint64(header[224:], uint64(s.At))
	sections := [][]byte{m, index, dedup, audit, stored}
	off := uint64(256)
	for i, section := range sections {
		x := header[96+24*i:]
		le.PutUint64(x, off)
		le.PutUint64(x[8:], uint64(len(section)))
		le.PutUint32(x[16:], checksum(section))
		off += uint64(len(section))
	}
	le.PutUint32(header[252:], checksum(header[:252]))
	out := header
	for _, section := range sections {
		out = append(out, section...)
	}
	// 生成側にも復号側と同じ全体の展開予算・相互照合を適用する。
	if _, e = DecodePack(out); e != nil {
		return nil, e
	}
	return out, nil
}

// DecodePack は全ブロックを展開し、DATハッシュ・索引・要約を検証する。
// この整合性検査だけでは元の受理操作を証明しない。公開前の証拠照合は別途必須。
func DecodePack(data []byte) (PackSnapshot, error) {
	s, sections, blocks, e := parsePack(data)
	if e != nil {
		return PackSnapshot{}, e
	}
	budget := MaxPackFile
	for _, b := range blocks {
		if uint64(b.chunk.RawLength) > uint64(budget) {
			return PackSnapshot{}, ErrCorrupt
		}
		budget -= int(b.chunk.RawLength)
		posts, lines, seqs, err := decodePackBlock(b, s.State.Revision)
		if err != nil {
			return PackSnapshot{}, err
		}
		s.State.Posts = append(s.State.Posts, posts...)
		s.State.Lines = append(s.State.Lines, lines...)
		s.Origins = append(s.Origins, seqs...)
	}
	if e = domain.ValidateSnapshot(s.State); e != nil {
		return PackSnapshot{}, e
	}
	var meta packMetadata
	if e = strictjson.Decode(sections[0], &meta); e != nil {
		return PackSnapshot{}, e
	}
	hash := sha256.New()
	for _, line := range s.State.Lines {
		_, _ = hash.Write(line)
	}
	if !bytes.Equal(hash.Sum(nil), meta.DATHash[:]) {
		return PackSnapshot{}, ErrCorrupt
	}
	if s.Dedup, e = decodePackDedup(sections[2], s); e != nil {
		return PackSnapshot{}, e
	}
	if s.Audit, e = decodePackAudit(sections[3], s, &budget); e != nil {
		return PackSnapshot{}, e
	}
	return s, nil
}

func parsePack(data []byte) (PackSnapshot, [][]byte, []packBlock, error) {
	fail := func() (PackSnapshot, [][]byte, []packBlock, error) { return PackSnapshot{}, nil, nil, ErrCorrupt }
	if len(data) < 256 || len(data) > MaxPackFile {
		return fail()
	}
	h := data[:256]
	if string(h[:8]) != "OIMOPAK1" || le.Uint16(h[8:]) != 1 || le.Uint16(h[10:]) != 256 || le.Uint32(h[12:]) != 0 || !bytes.Equal(h[232:252], make([]byte, 20)) || le.Uint32(h[252:]) != checksum(h[:252]) || le.Uint64(h[216:]) != uint64(len(data)) {
		return fail()
	}
	s := PackSnapshot{Key: le.Uint64(h[32:]), Generation: le.Uint64(h[40:]), At: domain.Time(le.Uint64(h[224:]))}
	copy(s.Owner[:], h[16:32])
	count, blockCount := le.Uint32(h[80:]), le.Uint32(h[84:])
	base := domain.U64(le.Uint64(h[48:]))
	if s.Owner == (domain.ID{}) || s.Key == 0 || s.Generation == 0 || base == 0 || count == 0 || count > MaxPackPosts || blockCount == 0 || blockCount > count || le.Uint64(h[88:]) > MaxPackFile {
		return fail()
	}
	sections := make([][]byte, 5)
	off := uint64(256)
	for i := range sections {
		x := h[96+24*i:]
		pos, n := le.Uint64(x), le.Uint64(x[8:])
		if pos != off || n == 0 || n > uint64(len(data))-off || le.Uint32(x[20:]) != 0 {
			return fail()
		}
		sections[i] = data[off : off+n]
		if checksum(sections[i]) != le.Uint32(x[16:]) {
			return fail()
		}
		off += n
	}
	if off != uint64(len(data)) || len(sections[0]) > 1<<20 || uint64(len(sections[1])) != uint64(blockCount)*96 {
		return fail()
	}
	var m packMetadata
	if e := strictjson.Decode(sections[0], &m); e != nil {
		return PackSnapshot{}, nil, nil, e
	}
	if m.Revision != base || uint64(m.Created) != le.Uint64(h[64:]) || uint64(m.Expires) != le.Uint64(h[72:]) || m.After.PostCount != count || uint64(m.After.DATBytes) != le.Uint64(h[88:]) || uint64(m.After.DATGeneration) != le.Uint64(h[56:]) || m.After.DATGeneration == 0 || s.At >= m.Expires {
		return fail()
	}
	s.State = &domain.Thread{Revision: m.Revision, Title: m.Title, Created: m.Created, Expires: m.Expires, After: m.After, Policy: m.Policy}
	s.LastOperation = m.LastOperation
	if m.Move != nil {
		if *m.Move == "" {
			return fail()
		}
		s.State.MoveTarget = *m.Move
	}
	blocks := make([]packBlock, 0, int(blockCount))
	number := uint64(1)
	datPos := uint64(0)
	physical := le.Uint64(h[192:])
	rawBudget := uint64(MaxPackFile)
	for i := uint32(0); i < blockCount; i++ {
		x := sections[1][int(i)*96 : int(i+1)*96]
		if le.Uint16(x[42:]) != 0 || le.Uint32(x[88:]) != 0 || le.Uint32(x[92:]) != checksum(x[:92]) {
			return fail()
		}
		b := packBlock{first: le.Uint32(x), count: le.Uint32(x[4:]), start: le.Uint64(x[8:]), length: le.Uint64(x[16:]), offset: le.Uint64(x[24:]), users: le.Uint32(x[52:]), minTime: domain.Time(le.Uint64(x[56:])), maxTime: domain.Time(le.Uint64(x[64:])), minSeq: domain.U64(le.Uint64(x[72:])), maxSeq: domain.U64(le.Uint64(x[80:]))}
		stored, raw := uint64(le.Uint32(x[32:])), uint64(le.Uint32(x[36:]))
		if uint64(b.first) != number || b.count == 0 || uint64(b.count) > uint64(count)+1-number || b.start != datPos || b.length == 0 || b.length > uint64(m.After.DATBytes)-datPos || b.offset != physical || stored == 0 || stored > MaxPackStored || stored > uint64(len(data))-physical || raw == 0 || raw > MaxPackRaw || raw > rawBudget || b.users > b.count || b.minSeq == 0 || b.minSeq > b.maxSeq || b.maxSeq > base || b.minTime > b.maxTime || b.users == 0 && (b.minTime != 0 || b.maxTime != 0) {
			return fail()
		}
		b.chunk = PackChunk{x[40], x[41], uint32(raw), le.Uint32(x[48:]), le.Uint32(x[44:]), data[physical : physical+stored]}
		if !validPackPolicy(b.chunk.Codec, b.chunk.Level) {
			return fail()
		}
		number += uint64(b.count)
		datPos += b.length
		physical += stored
		rawBudget -= raw
		blocks = append(blocks, b)
	}
	if number != uint64(count)+1 || datPos != uint64(m.After.DATBytes) || physical != uint64(len(data)) {
		return fail()
	}
	return s, sections, blocks, nil
}

// ReadPackDAT は検証済みpackに対し、要求区間に重なるブロックだけを展開する。
// 初回設置・公開前にはDecodePackによる全構造と証拠照合が必要。位置はDATのbyte単位。
func ReadPackDAT(data []byte, start, end uint64) ([]byte, error) {
	s, _, blocks, e := parsePack(data)
	if e != nil {
		return nil, e
	}
	if start > end || end > uint64(s.State.After.DATBytes) {
		return nil, ErrCorrupt
	}
	out := make([]byte, 0, int(end-start))
	for _, b := range blocks {
		lo, hi := max(start, b.start), min(end, b.start+b.length)
		if lo >= hi {
			continue
		}
		_, lines, _, e := decodePackBlock(b, s.State.Revision)
		if e != nil {
			return nil, e
		}
		pos := b.start
		for _, line := range lines {
			next := pos + uint64(len(line))
			a, z := max(lo, pos), min(hi, next)
			if a < z {
				out = append(out, line[a-pos:z-pos]...)
			}
			pos = next
		}
	}
	return out, nil
}
