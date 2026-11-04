// Package http3native は独自QUICサーバー上でHTTP/3と有界なQPACK動的圧縮を提供する。
package http3native

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
	"oimobbs/internal/quicv1"
)

// Field はHTTP/3の小文字field名と値。pseudo-headerも同じ表現で扱う。
type Field struct{ Name, Value string }
type entry struct {
	Field
	absolute uint64
	size     int
}
type table struct {
	entries        []entry
	size, capacity int
	count          uint64
}

func (t *table) lookup(f Field) (entry, bool) {
	for i := len(t.entries) - 1; i >= 0; i-- {
		if t.entries[i].Field == f {
			return t.entries[i], true
		}
	}
	return entry{}, false
}
func (t *table) at(index uint64) (Field, bool) {
	for _, e := range t.entries {
		if e.absolute == index {
			return e.Field, true
		}
	}
	return Field{}, false
}
func (t *table) insert(f Field, protected map[uint64]int) (entry, bool) {
	size := len(f.Name) + len(f.Value) + 32
	if size > t.capacity {
		return entry{}, false
	}
	remove := 0
	available := t.capacity - t.size
	for available < size && remove < len(t.entries) {
		e := t.entries[remove]
		if protected[e.absolute] > 0 {
			return entry{}, false
		}
		available += e.size
		remove++
	}
	for _, e := range t.entries[:remove] {
		t.size -= e.size
	}
	t.entries = t.entries[remove:]
	e := entry{Field: f, absolute: t.count, size: size}
	t.count++
	t.size += size
	t.entries = append(t.entries, e)
	return e, true
}

func appendPrefix(dst []byte, prefix byte, bits uint, v uint64) []byte {
	limit := uint64(1<<bits - 1)
	if v < limit {
		return append(dst, prefix|byte(v))
	}
	dst = append(dst, prefix|byte(limit))
	v -= limit
	for v >= 128 {
		dst = append(dst, byte(v&127)|128)
		v >>= 7
	}
	return append(dst, byte(v))
}
func readPrefix(first byte, bits uint, r io.ByteReader) (uint64, error) {
	limit := uint64(1<<bits - 1)
	v := uint64(first) & limit
	if v < limit {
		return v, nil
	}
	shift := uint(0)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if shift >= 63 || uint64(b&127) > (uint64(1<<62-1)-v)>>shift {
			return 0, errors.New("QPACK integer overflow")
		}
		v += uint64(b&127) << shift
		if b&128 == 0 {
			return v, nil
		}
		shift += 7
	}
}

type fieldReader struct {
	*bytes.Reader
	data []byte
}

// readString は長さ検証後に入力を参照し、中間bufferを複製しない。
func readString(first byte, bits uint, huffFlag byte, r *fieldReader) (string, error) {
	data, err := stringData(first, bits, r)
	if err != nil {
		return "", err
	}
	if first&huffFlag == 0 {
		return string(data), nil
	}
	return decodeHuffman(data)
}

// stringData は入力の残量と文字列上限を検証し、当該sectionの範囲だけを返す。
func stringData(first byte, bits uint, r *fieldReader) ([]byte, error) {
	length, err := readPrefix(first, bits, r)
	if err != nil || length > uint64(r.Len()) || length > 16<<10 {
		return nil, errors.New("QPACK string bound")
	}
	start := len(r.data) - r.Len()
	data := r.data[start : start+int(length)]
	_, _ = r.Seek(int64(length), io.SeekCurrent)
	return data, nil
}

func decodeHuffman(data []byte) (string, error) {
	value, err := hpack.HuffmanDecodeToString(data)
	if err != nil || len(value) > 16<<10 {
		return "", errors.New("QPACK Huffman bound")
	}
	return value, nil
}
func appendString(dst []byte, prefix byte, bits uint, huffFlag byte, value string) []byte {
	size := hpack.HuffmanEncodeLength(value)
	if size < uint64(len(value)) {
		dst = appendPrefix(dst, prefix|huffFlag, bits, uint64(size))
		return hpack.AppendHuffmanString(dst, value)
	}
	dst = appendPrefix(dst, prefix, bits, uint64(len(value)))
	return append(dst, value...)
}

var staticExact, staticNames = indexStatic()

// indexStatic は規格の固定tableから読取り専用indexを一度だけ生成する。
func indexStatic() (map[Field]int, map[string]int) {
	exact := make(map[Field]int, len(staticFields))
	names := make(map[string]int, len(staticFields))
	for i, f := range staticFields {
		exact[f] = i
		if _, ok := names[f.Name]; !ok {
			names[f.Name] = i
		}
	}
	return exact, names
}
func staticIndex(f Field) (int, bool)    { i, ok := staticExact[f]; return i, ok }
func staticName(name string) (int, bool) { i, ok := staticNames[name]; return i, ok }

// dynamicAllowed は掲示板の公開キャッシュ・配信headerに動的tableの対象を限定する。
// 認証情報や任意の業務headerを接続間の圧縮履歴へ残さない。
func dynamicAllowed(name string) bool {
	switch name {
	case "etag", "date", "last-modified", "cache-control", "content-type", "content-encoding", "content-length", "accept-ranges", "vary", "x-content-type-options", "strict-transport-security", "permissions-policy", "referrer-policy":
		return true
	}
	return false
}
func sensitive(name string) bool {
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie":
		return true
	}
	return false
}
func literal(dst []byte, f Field) []byte {
	never := byte(0)
	if sensitive(f.Name) {
		never = 0x20
	}
	if index, ok := staticName(f.Name); ok {
		dst = appendPrefix(dst, 0x50|never, 4, uint64(index))
	} else {
		dst = appendString(dst, 0x20|never>>1, 3, 8, f.Name)
	}
	return appendString(dst, 0, 7, 0x80, f.Value)
}

type section struct {
	required uint64
	refs     []uint64
}

// QPACK は接続ごとに送受信別の動的tableを持つ。最大4KiB・16 blocked streamsに固定する。
type QPACK struct {
	mu               sync.Mutex
	tx, rx           table
	peerCapacity     uint64
	peerBlocked      uint64
	known            uint64
	protected        map[uint64]int
	sections         map[uint64][]section
	encoder, decoder *quicv1.Stream
	openStream       func(byte) (*quicv1.Stream, error)
	rxKnown          uint64
	changed          chan struct{}
	blocked          int
	literals         map[Field][]byte
	literalBytes     int
	values           map[string]string
	valueBytes       int
}

func newQPACK(encoder, decoder *quicv1.Stream) *QPACK {
	return &QPACK{encoder: encoder, decoder: decoder, protected: make(map[uint64]int), sections: make(map[uint64][]section), changed: make(chan struct{})}
}

func (q *QPACK) configure(capacity, blocked uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.peerCapacity = capacity
	q.peerBlocked = blocked
	q.tx.capacity = int(min(capacity, 4096))
	if q.tx.capacity == 0 {
		return nil
	}
	return q.writeControl(&q.encoder, 2, appendPrefix(nil, 0x20, 5, uint64(q.tx.capacity)))
}

// writeControl は必要になるまでQPACK専用streamを開かず、静的圧縮のpeerに余分な送信をしない。
// q.muを保持して呼び、複数の命令を同じ順序で送る。
func (q *QPACK) writeControl(stream **quicv1.Stream, kind byte, data []byte) error {
	if *stream == nil {
		if q.openStream == nil {
			return nil
		}
		opened, err := q.openStream(kind)
		if err != nil {
			return err
		}
		*stream = opened
	}
	_ = (*stream).SetWriteDeadline(time.Now().Add(5 * time.Second))
	for len(data) > 0 {
		n := min(len(data), 4096)
		if _, err := (*stream).WriteQueued(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// encode は未ACK参照のあるentryを追い出さず、peerのblocked上限内だけ動的参照を使う。
func (q *QPACK) encode(streamID uint64, fields []Field) ([]byte, error) {
	return q.encodeInto(streamID, fields, nil)
}

// encodeInto は呼出元所有の作業領域を使い、送信先がコピーするまで内容を保持する。
func (q *QPACK) encodeInto(streamID uint64, fields []Field, dst []byte) ([]byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.tx.capacity == 0 || !q.dynamicWorthwhile(fields) {
		out := append(dst, 0, 0)
		for _, f := range fields {
			if index, ok := staticIndex(f); ok {
				out = appendPrefix(out, 0xc0, 6, uint64(index))
			} else {
				out = q.appendLiteral(out, f)
			}
		}
		return out, nil
	}
	refs := make([]uint64, 0, len(fields))
	selected := make([]*entry, len(fields))
	var instructions []byte
	blocked := uint64(0)
	for _, sections := range q.sections {
		for _, s := range sections {
			if s.required > q.known {
				blocked++
				break
			}
		}
	}
	canBlock := blocked < q.peerBlocked
	outstanding := 0
	for _, sections := range q.sections {
		outstanding += len(sections)
	}
	for i, f := range fields {
		if !dynamicAllowed(f.Name) || outstanding >= 128 {
			continue
		}
		if _, ok := staticIndex(f); ok {
			continue
		}
		e, exists := q.tx.lookup(f)
		if !exists && q.tx.capacity > 0 {
			if inserted, ok := q.tx.insert(f, q.protected); ok {
				e = inserted
				exists = true
				instructions = appendString(instructions, 0x40, 5, 0x20, f.Name)
				instructions = appendString(instructions, 0, 7, 0x80, f.Value)
			}
		}
		if exists && (e.absolute < q.known || canBlock) {
			v := e
			selected[i] = &v
			refs = append(refs, e.absolute)
			q.protected[e.absolute]++
		}
	}
	if len(instructions) > 0 {
		if err := q.writeControl(&q.encoder, 2, instructions); err != nil {
			return nil, err
		}
	}
	required := uint64(0)
	for _, index := range refs {
		required = max(required, index+1)
	}
	base := q.tx.count
	encoded := uint64(0)
	if required > 0 {
		full := 2 * (q.peerCapacity / 32)
		if full == 0 {
			return nil, errors.New("QPACK dynamic reference without capacity")
		}
		encoded = required%full + 1
	}
	out := appendPrefix(dst, 0, 8, encoded)
	out = appendPrefix(out, 0, 7, base-required)
	for i, f := range fields {
		if index, ok := staticIndex(f); ok {
			out = appendPrefix(out, 0xc0, 6, uint64(index))
			continue
		}
		if e := selected[i]; e != nil {
			out = appendPrefix(out, 0x80, 6, base-e.absolute-1)
			continue
		}
		out = q.appendLiteral(out, f)
	}
	if len(refs) > 0 {
		q.sections[streamID] = append(q.sections[streamID], section{required: required, refs: refs})
	}
	return out, nil
}

func (q *QPACK) required(encoded uint64) (uint64, error) {
	if encoded == 0 {
		return 0, nil
	}
	maxEntries := uint64(4096 / 32)
	full := 2 * maxEntries
	if encoded > full {
		return 0, errors.New("QPACK required insert count range")
	}
	maximum := q.rx.count + maxEntries
	wrapped := (maximum / full) * full
	value := wrapped + encoded - 1
	if value > maximum {
		if value <= full {
			return 0, errors.New("QPACK invalid wrapped insert count")
		}
		value -= full
	}
	if value == 0 {
		return 0, errors.New("QPACK zero required insert count")
	}
	return value, nil
}

// decode は未着のencoder命令を期限付きで待ち、展開後16KiBを超えるfield sectionを拒否する。
func (q *QPACK) decode(ctx context.Context, streamID uint64, data []byte, deadline ...time.Time) ([]Field, error) {
	if len(data) > 16<<10 {
		return nil, errors.New("QPACK header block too large")
	}
	r := &fieldReader{Reader: bytes.NewReader(data), data: data}
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	encoded, err := readPrefix(first, 8, r)
	if err != nil {
		return nil, err
	}
	q.mu.Lock()
	required, err := q.required(encoded)
	q.mu.Unlock()
	if err != nil {
		return nil, err
	}
	first, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	delta, err := readPrefix(first, 7, r)
	if err != nil {
		return nil, err
	}
	base := required + delta
	if first&0x80 != 0 {
		if delta >= required {
			return nil, errors.New("QPACK negative base")
		}
		base = required - delta - 1
	}
	q.mu.Lock()
	waiting := false
	var timeout <-chan time.Time
	for q.rx.count < required {
		if !waiting {
			if q.blocked >= 16 {
				q.mu.Unlock()
				return nil, errors.New("QPACK blocked stream budget")
			}
			q.blocked++
			waiting = true
			if len(deadline) > 0 && !deadline[0].IsZero() {
				timer := time.NewTimer(max(time.Duration(0), time.Until(deadline[0])))
				defer timer.Stop()
				timeout = timer.C
			}
		}
		changed := q.changed
		q.mu.Unlock()
		select {
		case <-changed:
		case <-timeout:
			q.mu.Lock()
			q.blocked--
			q.mu.Unlock()
			return nil, os.ErrDeadlineExceeded
		case <-ctx.Done():
			q.mu.Lock()
			q.blocked--
			q.mu.Unlock()
			return nil, ctx.Err()
		}
		q.mu.Lock()
	}
	if waiting {
		q.blocked--
	}
	fields, err := q.decodeFields(r, base, required)
	if err == nil && required > 0 {
		q.rxKnown = max(q.rxKnown, required)
		err = q.writeControl(&q.decoder, 3, appendPrefix(nil, 0x80, 7, streamID))
	}
	q.mu.Unlock()
	return fields, err
}
func (q *QPACK) decodeFields(r *fieldReader, base, required uint64) ([]Field, error) {
	out := make([]Field, 0, 8)
	total := 0
	for r.Len() > 0 {
		first, _ := r.ReadByte()
		var f Field
		var err error
		switch {
		case first&0x80 != 0:
			index, e := readPrefix(first, 6, r)
			err = e
			if err == nil {
				f, err = q.field(index, first&0x40 != 0, base, false, required)
			}
		case first&0xc0 == 0x40:
			index, e := readPrefix(first, 4, r)
			err = e
			if err == nil {
				f, err = q.field(index, first&0x10 != 0, base, false, required)
			}
			if err == nil {
				b, e := r.ReadByte()
				err = e
				if err == nil {
					f.Value, err = q.readValue(b, r, f.Name, first&0x20 == 0)
				}
			}
		case first&0xe0 == 0x20:
			f.Name, err = readString(first, 3, 8, r)
			if err == nil {
				b, e := r.ReadByte()
				err = e
				if err == nil {
					f.Value, err = q.readValue(b, r, f.Name, first&0x10 == 0)
				}
			}
		case first&0xf0 == 0x10:
			index, e := readPrefix(first, 4, r)
			err = e
			if err == nil {
				f, err = q.field(index, false, base, true, required)
			}
		default:
			index, e := readPrefix(first, 3, r)
			err = e
			if err == nil {
				f, err = q.field(index, false, base, true, required)
			}
			if err == nil {
				b, e := r.ReadByte()
				err = e
				if err == nil {
					f.Value, err = q.readValue(b, r, f.Name, first&0x08 == 0)
				}
			}
		}
		if err != nil {
			return nil, err
		}
		total += len(f.Name) + len(f.Value) + 32
		if total > 16<<10 || len(out) >= 256 {
			return nil, errors.New("QPACK decoded header budget")
		}
		out = append(out, f)
	}
	return out, nil
}
func (q *QPACK) field(index uint64, static bool, base uint64, post bool, required uint64) (Field, error) {
	if static {
		if index >= uint64(len(staticFields)) {
			return Field{}, errors.New("QPACK static index")
		}
		return staticFields[index], nil
	}
	absolute := base + index
	if !post {
		if index >= base {
			return Field{}, errors.New("QPACK relative index")
		}
		absolute = base - index - 1
	}
	if absolute >= required {
		return Field{}, errors.New("QPACK reference beyond required insert count")
	}
	f, ok := q.rx.at(absolute)
	if !ok {
		return Field{}, errors.New("QPACK evicted dynamic reference")
	}
	return f, nil
}

func readInstructionString(first byte, bits uint, huff byte, r *bufio.Reader) (string, error) {
	length, err := readPrefix(first, bits, r)
	if err != nil || length > 16<<10 {
		return "", errors.New("QPACK instruction string bound")
	}
	data := make([]byte, int(length))
	if _, err = io.ReadFull(r, data); err != nil {
		return "", err
	}
	if first&huff == 0 {
		return string(data), nil
	}
	value, err := hpack.HuffmanDecodeToString(data)
	if err != nil || len(value) > 16<<10 {
		return "", errors.New("QPACK instruction Huffman bound")
	}
	return value, nil
}

// readEncoder はclient encoder streamを逐次処理し、table容量と参照indexを検証する。
func (q *QPACK) readEncoder(reader io.Reader) error {
	r := bufio.NewReaderSize(reader, 4096)
	for {
		first, err := r.ReadByte()
		if err != nil {
			return err
		}
		var field Field
		var inserted bool
		switch {
		case first&0x80 != 0:
			index, err := readPrefix(first, 6, r)
			if err != nil {
				return err
			}
			q.mu.Lock()
			if first&0x40 != 0 {
				if index >= uint64(len(staticFields)) {
					q.mu.Unlock()
					return errors.New("QPACK encoder static index")
				}
				field = staticFields[index]
			} else {
				if index >= q.rx.count {
					q.mu.Unlock()
					return errors.New("QPACK encoder dynamic index")
				}
				var ok bool
				field, ok = q.rx.at(q.rx.count - index - 1)
				if !ok {
					q.mu.Unlock()
					return errors.New("QPACK encoder evicted index")
				}
			}
			q.mu.Unlock()
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			field.Value, err = readInstructionString(b, 7, 0x80, r)
			if err != nil {
				return err
			}
			inserted = true
		case first&0xc0 == 0x40:
			field.Name, err = readInstructionString(first, 5, 0x20, r)
			if err != nil {
				return err
			}
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			field.Value, err = readInstructionString(b, 7, 0x80, r)
			if err != nil {
				return err
			}
			inserted = true
		case first&0xe0 == 0x20:
			capacity, err := readPrefix(first, 5, r)
			if err != nil || capacity > 4096 {
				return errors.New("QPACK capacity exceeds setting")
			}
			q.mu.Lock()
			q.rx.capacity = int(capacity)
			for q.rx.size > q.rx.capacity {
				q.rx.size -= q.rx.entries[0].size
				q.rx.entries = q.rx.entries[1:]
			}
			q.mu.Unlock()
		default:
			index, err := readPrefix(first, 5, r)
			if err != nil {
				return err
			}
			q.mu.Lock()
			if index >= q.rx.count {
				q.mu.Unlock()
				return errors.New("QPACK duplicate index")
			}
			var ok bool
			field, ok = q.rx.at(q.rx.count - index - 1)
			q.mu.Unlock()
			if !ok {
				return errors.New("QPACK duplicate evicted index")
			}
			inserted = true
		}
		if !inserted {
			continue
		}
		q.mu.Lock()
		_, ok := q.rx.insert(field, nil)
		if !ok {
			q.mu.Unlock()
			return errors.New("QPACK inserted entry exceeds capacity")
		}
		close(q.changed)
		q.changed = make(chan struct{})
		increment := q.rx.count - q.rxKnown
		q.rxKnown = q.rx.count
		if increment > 0 {
			err = q.writeControl(&q.decoder, 3, appendPrefix(nil, 0, 6, increment))
		}
		q.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

// readDecoder はpeerがACKしたsectionだけ参照保護を解放し、不正なACKを拒否する。
func (q *QPACK) readDecoder(reader io.Reader) error {
	r := bufio.NewReaderSize(reader, 1024)
	for {
		first, err := r.ReadByte()
		if err != nil {
			return err
		}
		bits := uint(6)
		if first&0x80 != 0 {
			bits = 7
		}
		value, err := readPrefix(first, bits, r)
		if err != nil {
			return err
		}
		q.mu.Lock()
		if first&0xc0 == 0 {
			if value == 0 || value > q.tx.count-q.known {
				q.mu.Unlock()
				return errors.New("QPACK insert count increment")
			}
			q.known += value
			q.mu.Unlock()
			continue
		}
		sections := q.sections[value]
		if len(sections) == 0 && first&0x80 == 0 {
			q.mu.Unlock()
			continue
		}
		if len(sections) == 0 {
			q.mu.Unlock()
			return errors.New("QPACK unknown section acknowledgment")
		}
		count := 1
		if first&0x80 == 0 {
			count = len(sections)
		}
		for _, s := range sections[:count] {
			for _, ref := range s.refs {
				q.protected[ref]--
				if q.protected[ref] == 0 {
					delete(q.protected, ref)
				}
			}
			if first&0x80 != 0 {
				q.known = max(q.known, s.required)
			}
		}
		if count == len(sections) {
			delete(q.sections, value)
		} else {
			q.sections[value] = sections[count:]
		}
		q.mu.Unlock()
	}
}
