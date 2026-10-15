// 保存専用Zstandardを一つの作業器で生成し、圧縮器のCPU・メモリを有界にする。
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
	archiveMutex.Lock()
	defer archiveMutex.Unlock()
	profiles := archiveProfiles(level)
	var best []byte
	for _, profile := range profiles {
		candidate, err := archiveEncoder.EncodeArchive(raw, profile)
		if err != nil {
			return PackChunk{}, err
		}
		if best == nil || len(candidate) < len(best) {
			best = candidate
		}
	}
	if len(best) > MaxPackStored {
		return PackChunk{}, ErrCorrupt
	}
	// 圧縮器から返る配列は専有。入力を保持せず、他呼出から変更されない。
	return PackChunk{Codec: 2, Level: level, RawLength: uint32(len(raw)), RawCRC: checksum(raw), StoredCRC: checksum(best), Stored: best}, nil
}

// archiveProfiles は測定済みの候補数だけを使い、若いスレッドの整理を軽くする。
func archiveProfiles(level uint8) []zstdencode.ArchiveOptions {
	switch level {
	case 1:
		return []zstdencode.ArchiveOptions{{HashBytes: 0, AccuracyLog: 7}}
	case 6:
		return []zstdencode.ArchiveOptions{{HashBytes: 0, AccuracyLog: 8}}
	default:
		return []zstdencode.ArchiveOptions{{HashBytes: 0, AccuracyLog: 8}, {HashBytes: 0, AccuracyLog: 9}, {HashBytes: 7, AccuracyLog: 8}, {HashBytes: 4, AccuracyLog: 9}}
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
