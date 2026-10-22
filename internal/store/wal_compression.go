// 正規frameのhashを維持したまま、同じSync対象のWAL batchを有界Zstandard blockへ保存する。
package store

import (
	"bytes"
	"errors"
	"io"
	"oimobbs/internal/zstddecode"
	"oimobbs/internal/zstdencode"
	"sync"
)

const walCompressedFlag uint32 = 1 << 31
const maxWALRaw = MaxFrameBody + 20

// 小さい単独Syncでは既存のbyte数と処理量を維持し、圧縮は到着済みbatchと大きい記録へ使う。
const minSingleWALCompression = 32 << 10

var walEncoders = sync.Pool{New: func() any { return &zstdencode.Encoder{} }}

// EncodeWALBlock は最大64正規frameを同じSync単位で圧縮する。署名済みの正規byteは変更しない。
// 32KiB未満の単独frame、および圧縮外枠込みで小さくならない列はrawで保存し、既存のサイズを超えない。
func EncodeWALBlock(frames [][]byte) ([]byte, error) {
	if len(frames) == 0 || len(frames) > MaxCommitFrames {
		return nil, ErrCorrupt
	}
	size := 0
	for _, raw := range frames {
		if len(raw) > maxWALRaw-size {
			return nil, ErrCorrupt
		}
		_, err := decodeFrameView(raw)
		if err != nil {
			return nil, ErrCorrupt
		}
		size += len(raw)
	}
	if len(frames) == 1 && size < minSingleWALCompression {
		return bytes.Clone(frames[0]), nil
	}
	raw := bytes.Join(frames, nil)
	encoder := walEncoders.Get().(*zstdencode.Encoder)
	compressed, err := encoder.EncodeBestArchive(raw, []zstdencode.ArchiveOptions{{AccuracyLog: 7}})
	walEncoders.Put(encoder)
	if err != nil {
		return nil, err
	}
	if len(compressed)+28 >= len(raw) {
		return raw, nil
	}
	body := make([]byte, 8, len(compressed)+8)
	le.PutUint32(body, uint32(len(raw)))
	le.PutUint32(body[4:], checksum(raw))
	body = append(body, compressed...)
	result := make([]byte, 8, len(body)+20)
	le.PutUint32(result, uint32(len(body))|walCompressedFlag)
	le.PutUint32(result[4:], checksum(result[:4]))
	result = append(result, body...)
	result = le.AppendUint32(result, checksum(body))
	result = append(result, "OIMOEND2"...)
	return result, nil
}

// encodeWALSeries は既存の64frame blockを連結するだけで、新しい永続形式を導入しない。
// 大きい列も全体8MiBの既存予算内に収める。64件以下の圧縮結果は従来と完全に同じ。
func encodeWALSeries(frames [][]byte) ([]byte, error) {
	if len(frames) == 0 || len(frames) > MaxCommitSeriesFrames {
		return nil, ErrCorrupt
	}
	if len(frames) <= MaxCommitFrames {
		return EncodeWALBlock(frames)
	}
	var blocks [][]byte
	for start := 0; start < len(frames); start += MaxCommitFrames {
		block, err := EncodeWALBlock(frames[start:min(start+MaxCommitFrames, len(frames))])
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	return bytes.Join(blocks, nil), nil
}

// ReadWALBlock は新世代WALの一保存単位を読む。圧縮長・展開長・CRC・終端・全frame数を検査する。
// 末尾の不足はErrIncomplete、完全な破損はErrCorruptとして区別し、部分frameは返さない。
func ReadWALBlock(reader io.Reader) ([]Frame, int64, error) {
	prefix := make([]byte, 8)
	n, err := io.ReadFull(reader, prefix)
	if err != nil {
		if errors.Is(err, io.EOF) && n == 0 {
			return nil, 0, io.EOF
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, int64(n), ErrIncomplete
		}
		return nil, int64(n), err
	}
	length := le.Uint32(prefix)
	if checksum(prefix[:4]) != le.Uint32(prefix[4:]) {
		return nil, 8, ErrCorrupt
	}
	if length&walCompressedFlag == 0 {
		frame, size, err := ReadFrame(io.MultiReader(bytes.NewReader(prefix), reader))
		if err != nil {
			return nil, size, err
		}
		return []Frame{frame}, size, nil
	}
	length &^= walCompressedFlag
	if length < 14 || length > maxWALRaw {
		return nil, 8, ErrCorrupt
	}
	body := make([]byte, int(length)+12)
	n, err = io.ReadFull(reader, body)
	size := int64(n) + 8
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, size, ErrIncomplete
	}
	if err != nil {
		return nil, size, err
	}
	if checksum(body[:length]) != le.Uint32(body[length:]) || string(body[length+4:]) != "OIMOEND2" {
		return nil, size, ErrCorrupt
	}
	rawSize := le.Uint32(body)
	raw, err := zstddecode.DecodeBounded(body[8:length], int(rawSize), maxWALRaw)
	if err != nil || checksum(raw) != le.Uint32(body[4:]) {
		return nil, size, ErrCorrupt
	}
	input := bytes.NewReader(raw)
	var frames []Frame
	for input.Len() > 0 {
		if len(frames) >= MaxCommitFrames {
			return nil, size, ErrCorrupt
		}
		frame, _, err := ReadFrame(input)
		if err != nil {
			return nil, size, ErrCorrupt
		}
		frames = append(frames, frame)
	}
	if len(frames) == 0 {
		return nil, size, ErrCorrupt
	}
	return frames, size, nil
}
