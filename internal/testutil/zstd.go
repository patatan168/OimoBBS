// Package testutil は製品に含めない検証補助を提供する。
package testutil

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// DecodeZstd は内容長付きの送信frameを標準ライブラリの独立decoderで検証する。
// ELFの圧縮sectionを経由するのは、GoのZstandard decoderが内部packageだからである。
// 復号器は製品で使用しない。検証時の確保量は16MiB以下に制限する。
func DecodeZstd(frame []byte) ([]byte, error) {
	if len(frame) < 6 || !bytes.Equal(frame[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) || frame[4]&0x1f != 0 {
		return nil, fmt.Errorf("unexpected test frame header")
	}
	flag := frame[4] >> 6
	single := frame[4]&0x20 != 0
	width := []int{1, 2, 4, 8}[flag]
	start := 5
	if !single {
		start++
	}
	if flag == 0 && !single || len(frame) < start+width {
		return nil, fmt.Errorf("missing content size")
	}
	var size uint64
	for i := range width {
		size |= uint64(frame[start+i]) << uint(8*i)
	}
	if width == 2 {
		size += 256
	}
	if size > 16<<20 {
		return nil, fmt.Errorf("test decode limit")
	}
	file := make([]byte, 216, len(frame)+216)
	copy(file, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	bo := binary.LittleEndian
	bo.PutUint16(file[16:], 1)
	bo.PutUint16(file[18:], 62)
	bo.PutUint32(file[20:], 1)
	bo.PutUint64(file[40:], 64)
	bo.PutUint16(file[52:], 64)
	bo.PutUint16(file[58:], 64)
	bo.PutUint16(file[60:], 2)
	bo.PutUint32(file[132:], uint32(elf.SHT_PROGBITS))
	bo.PutUint64(file[136:], uint64(elf.SHF_COMPRESSED))
	bo.PutUint64(file[152:], 192)
	bo.PutUint64(file[160:], uint64(len(frame)+24))
	bo.PutUint64(file[176:], 1)
	bo.PutUint32(file[192:], uint32(elf.COMPRESS_ZSTD))
	bo.PutUint64(file[200:], size)
	bo.PutUint64(file[208:], 1)
	file = append(file, frame...)
	reader, err := elf.NewFile(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return reader.Sections[1].Data()
}
