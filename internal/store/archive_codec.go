// 保存用Zstandardを再利用し、旧level 9の追加候補探索を省く。
package store

import (
	"bytes"
	"oimobbs/internal/zstdencode"
	"sync"
)

var archiveMutex sync.Mutex
var archiveEncoder zstdencode.Encoder

// EncodePackChunk は非圧縮または保存用Zstandardを生成する。Levelは年齢別の生成方針。
func EncodePackChunk(raw []byte, level uint8) (PackChunk, error) {
	if len(raw) == 0 || len(raw) > MaxPackRaw || !packLevel(level) {
		return PackChunk{}, ErrCorrupt
	}
	if level == 0 {
		return PackChunk{Level: 0, RawLength: uint32(len(raw)), RawCRC: checksum(raw), StoredCRC: checksum(raw), Stored: bytes.Clone(raw)}, nil
	}
	best, err := encodeStoredZstd(raw, level)
	if err != nil {
		return PackChunk{}, err
	}
	if len(best) > MaxPackStored {
		return PackChunk{}, ErrCorrupt
	}
	// 圧縮器から返る配列は専有。入力を保持せず、他呼出から変更されない。
	return PackChunk{Codec: 2, Level: level, RawLength: uint32(len(raw)), RawCRC: checksum(raw), StoredCRC: checksum(best), Stored: best}, nil
}

// encodeStoredZstd は保存用の同じ候補規則をsnapshotにも適用し、作業器を共有する。
func encodeStoredZstd(raw []byte, level uint8) ([]byte, error) {
	if level != 1 && level != 6 && level != 9 {
		return nil, ErrCorrupt
	}
	archiveMutex.Lock()
	defer archiveMutex.Unlock()
	if level == 9 {
		// 既存metadataの9は受理するが、追加探索せず配信用と同じ単一経路を使う。
		if len(raw) > (8<<20)+20 {
			return nil, ErrCorrupt
		}
		return archiveEncoder.Encode(raw), nil
	}
	return archiveEncoder.EncodeBestArchive(raw, archiveProfiles(level))
}

// archiveProfiles は測定済みの候補数だけを使い、若いスレッドの整理を軽くする。
func archiveProfiles(level uint8) []zstdencode.ArchiveOptions {
	switch level {
	case 1:
		return []zstdencode.ArchiveOptions{{HashBytes: 0, AccuracyLog: 7}}
	case 6:
		return []zstdencode.ArchiveOptions{{HashBytes: 0, AccuracyLog: 8}}
	default:
		return nil
	}
}

// validPackPolicy は現行の非圧縮/Zstandardだけを受理する。
func validPackPolicy(codec, level uint8) bool {
	return packLevel(level) && (codec == 0 || codec == 2) && (codec == 0) == (level == 0)
}

// packCompressionCodec は検証済みpackの本文・監査で使用codecの最大識別値を返す。
func packCompressionCodec(raw []byte) uint8 {
	_, sections, blocks, _ := parsePack(raw)
	codec := uint8(0)
	for _, block := range blocks {
		codec = max(codec, block.chunk.Codec)
	}
	audit := sections[3]
	position := 32
	for i := uint32(0); i < le.Uint32(audit[24:]); i++ {
		codec = max(codec, audit[position+12])
		position += 24 + int(le.Uint32(audit[position+8:]))
	}
	return codec
}
