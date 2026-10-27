// 分類保存を長さ・CRC付きの単一Zstandard frameにし、割当前に展開上限を検査する。
package bootstrap

import (
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"oimobbs/internal/store"
	"oimobbs/internal/zstddecode"
	"oimobbs/internal/zstdencode"
)

const networkZstdReader uint32 = 102

var networkCRC = crc32.MakeTable(crc32.Castagnoli)

// compressNetworkZstd は辞書なしの保存用符号を使い、原本長とCRCを外枠へ束縛する。
func compressNetworkZstd(body []byte) (string, error) {
	if len(body) > countryUnpackedLimit {
		return "", errNetworkData
	}
	var encoder zstdencode.Encoder
	frame, err := encoder.EncodeBestArchive(body, []zstdencode.ArchiveOptions{{HashBytes: 7, AccuracyLog: 9}})
	if err != nil {
		return "", err
	}
	raw := make([]byte, 12, len(frame)+12)
	copy(raw, "ONZ1")
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(body)))
	binary.LittleEndian.PutUint32(raw[8:], crc32.Checksum(body, networkCRC))
	raw = append(raw, frame...)
	return base64.StdEncoding.EncodeToString(raw), nil
}

// decompressNetworkZstd は余分なframe・末尾・改変・展開超過を拒否し、部分結果を返さない。
func decompressNetworkZstd(raw []byte, limit int) ([]byte, error) {
	if len(raw) < 12 || string(raw[:4]) != "ONZ1" || limit < 0 || limit > countryUnpackedLimit {
		return nil, errNetworkData
	}
	size := uint64(binary.LittleEndian.Uint32(raw[4:]))
	if size > uint64(limit) {
		return nil, errNetworkData
	}
	body, err := zstddecode.DecodeBounded(raw[12:], int(size), limit)
	if err != nil || crc32.Checksum(body, networkCRC) != binary.LittleEndian.Uint32(raw[8:]) {
		return nil, errNetworkData
	}
	return body, nil
}

// networkZstdValue は保存codecとreader102の境界を識別する。
func networkZstdValue(value string) bool { return len(value) >= 4 && value[:4] == "T05a" }

// decodeNetworkBase64 は分類専用の保存上限と正規base64を検査する。
func decodeNetworkBase64(value string) ([]byte, error) {
	if len(value) > store.MaxNetworkValueJSON {
		return nil, errNetworkData
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errNetworkData
	}
	return raw, nil
}
