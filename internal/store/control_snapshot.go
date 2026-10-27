// 制御snapshotの有界なraw/Zstandard codec。全行検査を終えてから復旧状態を返す。
package store

import (
	"bytes"
	"encoding/json"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/zstddecode"
	"slices"
	"sort"
	"strings"
)

const maxControlSnapshot = 64 << 20
const maxSnapshotChunk = 2 << 20
const maxSnapshotRows = 200000
const maxSnapshotChunks = 1024

type snapshotRow struct {
	Collection string          `json:"collection"`
	Key        string          `json:"key"`
	Revision   domain.U64      `json:"revision"`
	Expires    *domain.Time    `json:"expires_at_ns"`
	Value      json.RawMessage `json:"value"`
}

// snapshotHeader はsnapshot固有のmagic/chunk数を検査し、共通ヘッダの所有境界へ変換する。
func snapshotHeader(raw []byte, want Header) (uint32, error) {
	h, count, e := DecodeControlSnapshotHeader(raw)
	if e != nil || h != want {
		return 0, ErrCorrupt
	}
	return count, nil
}

// DecodeControlSnapshotHeader はsnapshotの先頭64bytesのCRC/形式/所有情報を検査する。
// 全chunk/行/署名の検査はDecodeControlSnapshotで別途必要。
func DecodeControlSnapshotHeader(raw []byte) (Header, uint32, error) {
	if len(raw) < 64 || string(raw[:8]) != "OIMOCSN2" || checksum(raw[:60]) != le.Uint32(raw[60:64]) {
		return Header{}, 0, ErrCorrupt
	}
	count := le.Uint32(raw[56:60])
	if count > maxSnapshotChunks {
		return Header{}, 0, ErrCorrupt
	}
	hb := bytes.Clone(raw[:64])
	copy(hb, "OIMOCTL2")
	le.PutUint32(hb[56:], 0)
	le.PutUint32(hb[60:], checksum(hb[:60]))
	h, e := DecodeHeader(hb)
	if e != nil || h.Kind == 0 {
		return Header{}, 0, ErrCorrupt
	}
	return h, count, nil
}

func validateSnapshotRow(row snapshotRow, h Header, validate ValueValidator) error {
	if validate == nil || !slices.Contains(controlCollections[h.Kind], row.Collection) || len(row.Key) > 160 || !controlKey.MatchString(row.Key) || row.Revision == 0 || uint64(row.Revision) > h.BaseSeq || len(row.Value) == 0 || bytes.Equal(bytes.TrimSpace(row.Value), []byte("null")) {
		return ErrCorrupt
	}
	if e := validateStoredControlValue(row.Collection, row.Key, row.Value); e != nil {
		return e
	}
	return validate(row.Collection, row.Key, nil, row.Value)
}

// DecodeControlSnapshot は指定の所有者・世代・seqへ束縛して復号する。部分状態を成功として返さない。
// 期限付き行も保持する。期限回収の判断は上位の保持・保全処理で行う。
func DecodeControlSnapshot(raw []byte, want Header, validate ValueValidator) (ControlState, error) {
	empty := ControlState{}
	if len(raw) > maxControlSnapshot || validate == nil {
		return empty, ErrCorrupt
	}
	count, e := snapshotHeader(raw, want)
	if e != nil {
		return empty, e
	}
	state := ControlState{Seq: domain.U64(want.BaseSeq), Rows: map[string]ControlRow{}}
	input := bytes.NewReader(raw[64:])
	total := 0
	last := ""
	for i := uint32(0); i < count; i++ {
		chunk := make([]byte, 32)
		if _, e = io.ReadFull(input, chunk); e != nil {
			return empty, ErrCorrupt
		}
		decoded, rows, e := decodeSnapshotChunk(input, chunk, maxControlSnapshot-total)
		if e != nil {
			return empty, e
		}
		total += len(decoded)
		reader := bytes.NewReader(decoded)
		for j := uint32(0); j < rows; j++ {
			var length [4]byte
			if _, e = io.ReadFull(reader, length[:]); e != nil {
				return empty, ErrCorrupt
			}
			n := le.Uint32(length[:])
			if n == 0 || n > MaxNetworkOperationJSON || int(n) > reader.Len() || len(state.Rows) >= maxSnapshotRows {
				return empty, ErrCorrupt
			}
			value := make([]byte, int(n))
			_, _ = io.ReadFull(reader, value)
			var row snapshotRow
			if e = strictjson.DecodeLimit(value, &row, MaxNetworkOperationJSON); e != nil {
				return empty, e
			}
			if e = validateSnapshotRow(row, want, validate); e != nil {
				return empty, e
			}
			key := row.Collection + ":" + row.Key
			if key <= last {
				return empty, ErrCorrupt
			}
			last = key
			state.Rows[key] = ControlRow{Revision: row.Revision, Expires: row.Expires, Value: bytes.Clone(row.Value)}
		}
		if reader.Len() != 0 {
			return empty, ErrCorrupt
		}
	}
	if input.Len() != 0 {
		return empty, ErrCorrupt
	}
	return state, nil
}

// decodeSnapshotChunk はCRCと単一Zstandard frame、宣言どおりの展開長を検査する。
func decodeSnapshotChunk(input *bytes.Reader, h []byte, remaining int) ([]byte, uint32, error) {
	rawSize, storedSize, rows := le.Uint32(h[8:]), le.Uint32(h[12:]), le.Uint32(h[16:])
	codec, level := h[20], h[21]
	if string(h[:8]) != "OIMOCBK2" || rawSize == 0 || rawSize > maxSnapshotChunk || int(rawSize) > remaining || storedSize == 0 || storedSize > maxSnapshotChunk+(64<<10) || int(storedSize) > input.Len() || rows == 0 || rows > rawSize/5 || le.Uint16(h[22:]) != 0 {
		return nil, 0, ErrCorrupt
	}
	if codec != 0 && codec != 2 || codec == 0 && (level != 0 || rawSize != storedSize) || codec == 2 && (level != 1 && level != 6 && level != 9) {
		return nil, 0, ErrCorrupt
	}
	stored := make([]byte, int(storedSize))
	_, _ = io.ReadFull(input, stored)
	if checksum(stored) != le.Uint32(h[28:]) {
		return nil, 0, ErrCorrupt
	}
	raw := stored
	if codec == 2 {
		var e error
		raw, e = zstddecode.DecodeBounded(stored, int(rawSize), maxSnapshotChunk)
		if e != nil {
			return nil, 0, ErrCorrupt
		}
	}
	if len(raw) != int(rawSize) || checksum(raw) != le.Uint32(h[24:]) {
		return nil, 0, ErrCorrupt
	}
	return raw, rows, nil
}

// EncodeControlSnapshot は全行を順序付け、revision・期限・値を維持して符号化する。
// levelは0(raw)/1/6/9のみ。ファイル設置やcurrent切替、行の回収は行わない。
func EncodeControlSnapshot(h Header, state ControlState, level int, validate ValueValidator) ([]byte, error) {
	if h.Kind == 0 || uint64(state.Seq) != h.BaseSeq || len(state.Rows) > maxSnapshotRows || validate == nil || (level != 0 && level != 1 && level != 6 && level != 9) {
		return nil, ErrCorrupt
	}
	header, e := EncodeHeader(h)
	if e != nil {
		return nil, e
	}
	copy(header, "OIMOCSN2")
	keys := make([]string, 0, len(state.Rows))
	for key := range state.Rows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := bytes.NewBuffer(header)
	chunk := []byte{}
	rows, count, total := uint32(0), uint32(0), 0
	flush := func() error {
		if rows == 0 {
			return nil
		}
		encoded, e := encodeSnapshotChunk(chunk, rows, level)
		if e != nil {
			return e
		}
		count++
		if count > maxSnapshotChunks || result.Len()+len(encoded) > maxControlSnapshot {
			return ErrCorrupt
		}
		result.Write(encoded)
		chunk = nil
		rows = 0
		return nil
	}
	for _, key := range keys {
		collection, name, ok := strings.Cut(key, ":")
		if !ok {
			return nil, ErrCorrupt
		}
		value := state.Rows[key]
		row := snapshotRow{collection, name, value.Revision, value.Expires, value.Value}
		if e = validateSnapshotRow(row, h, validate); e != nil {
			return nil, e
		}
		raw, e := json.Marshal(row)
		if e != nil || len(raw) > MaxNetworkOperationJSON {
			return nil, ErrCorrupt
		}
		if len(chunk)+4+len(raw) > maxSnapshotChunk {
			if e = flush(); e != nil {
				return nil, e
			}
		}
		total += 4 + len(raw)
		if total > maxControlSnapshot {
			return nil, ErrCorrupt
		}
		chunk = le.AppendUint32(chunk, uint32(len(raw)))
		chunk = append(chunk, raw...)
		rows++
	}
	if e = flush(); e != nil {
		return nil, e
	}
	out := result.Bytes()
	le.PutUint32(out[56:], count)
	le.PutUint32(out[60:], checksum(out[:60]))
	return out, nil
}
func encodeSnapshotChunk(raw []byte, rows uint32, level int) ([]byte, error) {
	stored := raw
	codec := byte(0)
	if level != 0 {
		compressed, e := encodeStoredZstd(raw, uint8(level))
		if e != nil {
			return nil, e
		}
		if len(compressed) < len(raw) {
			stored = compressed
			codec = 2
		} else {
			level = 0
		}
	}
	h := make([]byte, 32)
	copy(h, "OIMOCBK2")
	le.PutUint32(h[8:], uint32(len(raw)))
	le.PutUint32(h[12:], uint32(len(stored)))
	le.PutUint32(h[16:], rows)
	h[20] = codec
	h[21] = byte(level)
	le.PutUint32(h[24:], checksum(raw))
	le.PutUint32(h[28:], checksum(stored))
	return append(h, stored...), nil
}
