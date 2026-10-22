// pack本文ブロックと操作要約chunkに共通する、有界の圧縮・展開処理を提供する。
package store

import (
	"bytes"
	"oimobbs/internal/zstddecode"
)

const (
	// MaxPackRaw はJSONとレコード外枠を含む展開後サイズの上限。
	MaxPackRaw = 512 << 10
	// MaxPackStored は圧縮で増える場合も含めた保存サイズの上限。
	MaxPackStored = MaxPackRaw + 16<<10
)

// PackChunk は索引または監査chunkヘッダの検査値と保存バイト列。
// バイト列の構造・所有先・セクション境界は呼び出し側で別途検証する。
type PackChunk struct {
	Codec, Level      uint8
	RawLength         uint32
	RawCRC, StoredCRC uint32
	Stored            []byte
}

// DecodePackChunk は長さ・両CRC・Zstandard終端を検証し、独立した展開結果を返す。
// 宣言長以内に展開を制限し、破損時には部分結果を返さない。
// levelは生成方針の記録であり、圧縮streamから探索量は証明できない。
func DecodePackChunk(c PackChunk) ([]byte, error) {
	if c.RawLength == 0 || c.RawLength > MaxPackRaw || len(c.Stored) == 0 || len(c.Stored) > MaxPackStored || !packLevel(c.Level) {
		return nil, ErrCorrupt
	}
	if !validPackPolicy(c.Codec, c.Level) || checksum(c.Stored) != c.StoredCRC {
		return nil, ErrCorrupt
	}
	var raw []byte
	if c.Codec == 0 {
		if len(c.Stored) != int(c.RawLength) {
			return nil, ErrCorrupt
		}
		raw = bytes.Clone(c.Stored)
	} else {
		var err error
		raw, err = zstddecode.Decode(c.Stored, int(c.RawLength))
		if err != nil {
			return nil, ErrCorrupt
		}
	}
	if checksum(raw) != c.RawCRC {
		return nil, ErrCorrupt
	}
	return raw, nil
}

func packLevel(level uint8) bool { return level == 0 || level == 1 || level == 6 || level == 9 }
