// 共有再実行WALの有界な長さ・CRC・終端を検査し、個別WALの既存blockを保持する。
package store

import "oimobbs/internal/domain"

// encodeThreadGroup はowner/countと各key/generation/offset/length/blockを保存する。
// JSONの復号上限とBase64による膨張を避け、最大8MiBの本文batchをそのまま保護する。
func encodeThreadGroup(record threadGroupRecord) ([]byte, error) {
	if len(record.Writes) == 0 || len(record.Writes) > MaxCommitFrames {
		return nil, ErrCorrupt
	}
	size := 20
	for _, write := range record.Writes {
		if len(write.Block) == 0 || len(write.Block) > maxThreadGroupBytes-28-size-28 {
			return nil, ErrCorrupt
		}
		size += 28 + len(write.Block)
	}
	result := make([]byte, 16, size+28)
	copy(result, "OIMOGRP2")
	le.PutUint32(result[8:], uint32(size))
	le.PutUint32(result[12:], checksum(result[:12]))
	result = append(result, record.Owner[:]...)
	result = le.AppendUint32(result, uint32(len(record.Writes)))
	for _, write := range record.Writes {
		result = le.AppendUint64(result, uint64(write.Key))
		result = le.AppendUint64(result, uint64(write.Generation))
		result = le.AppendUint64(result, uint64(write.Offset))
		result = le.AppendUint32(result, uint32(len(write.Block)))
		result = append(result, write.Block...)
	}
	result = le.AppendUint32(result, checksum(result[16:]))
	return append(result, "OIMOENDG"...), nil
}

// decodeThreadGroups は完全な連続保存だけを返す。破損は拒否し、末尾の未完了保存は除外する。
func decodeThreadGroups(raw []byte) ([]threadGroupRecord, error) {
	if len(raw) > maxThreadGroupBytes {
		return nil, ErrCorrupt
	}
	var records []threadGroupRecord
	targets := 0
	for len(raw) > 0 {
		if len(raw) < 16 {
			break
		}
		if string(raw[:8]) != "OIMOGRP2" || le.Uint32(raw[12:]) != checksum(raw[:12]) {
			return nil, ErrCorrupt
		}
		size := int(le.Uint32(raw[8:]))
		if size < 20 || size > maxThreadGroupBytes-28 {
			return nil, ErrCorrupt
		}
		if len(raw) < size+28 {
			break
		}
		body := raw[16 : 16+size]
		if le.Uint32(raw[16+size:]) != checksum(body) || string(raw[20+size:28+size]) != "OIMOENDG" {
			return nil, ErrCorrupt
		}
		record, err := decodeThreadGroupBody(body)
		if err != nil {
			return nil, err
		}
		// 全recordの対象数も従来の64×64以内へ抑え、復号metadataを膨らませない。
		targets += len(record.Writes)
		if targets > maxThreadGroupFrames {
			return nil, ErrCorrupt
		}
		records = append(records, record)
		if len(records) > maxThreadGroupBatches {
			return nil, ErrCorrupt
		}
		raw = raw[size+28:]
	}
	return records, nil
}

// decodeThreadGroupBody は全長を照合してからblockの借用sliceを返す。復旧処理中だけ保持する。
func decodeThreadGroupBody(body []byte) (threadGroupRecord, error) {
	var record threadGroupRecord
	copy(record.Owner[:], body[:16])
	count := le.Uint32(body[16:])
	if count == 0 || count > MaxCommitFrames {
		return record, ErrCorrupt
	}
	body = body[20:]
	for range count {
		if len(body) < 28 {
			return threadGroupRecord{}, ErrCorrupt
		}
		size := uint64(le.Uint32(body[24:]))
		if size == 0 || size > uint64(len(body)-28) {
			return threadGroupRecord{}, ErrCorrupt
		}
		record.Writes = append(record.Writes, threadGroupWrite{Key: domain.U64(le.Uint64(body)), Generation: domain.U64(le.Uint64(body[8:])), Offset: int64(le.Uint64(body[16:])), Block: body[28 : 28+int(size)]})
		body = body[28+int(size):]
	}
	if len(body) != 0 {
		return threadGroupRecord{}, ErrCorrupt
	}
	return record, nil
}
