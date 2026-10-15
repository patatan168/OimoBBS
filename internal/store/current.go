// currentマニフェストの元byteハッシュと参照境界を検証する。
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

type Base struct {
	File          string      `json:"file"`
	Length        domain.U64  `json:"length"`
	SHA           domain.Hash `json:"sha256"`
	Seq           domain.U64  `json:"seq"`
	DATGeneration domain.U64  `json:"dat_generation"`
}
type Delta struct {
	File        string      `json:"file"`
	BaseSeq     domain.U64  `json:"base_seq"`
	RequiredSeq domain.U64  `json:"required_seq"`
	RequiredEnd domain.U64  `json:"required_end"`
	RequiredSHA domain.Hash `json:"required_sha256"`
}
type Manifest struct {
	Schema     uint32     `json:"schema"`
	BoardID    domain.ID  `json:"board_id"`
	ThreadKey  domain.U64 `json:"thread_key"`
	Generation domain.U64 `json:"storage_generation"`
	Base       *Base      `json:"base"`
	Delta      Delta      `json:"delta"`
}
type currentEnvelope struct {
	Manifest json.RawMessage `json:"manifest"`
	SHA      domain.Hash     `json:"manifest_sha256"`
}

// EncodeCurrent は一度だけ符号化したmanifestの元byteをハッシュする。
func EncodeCurrent(m Manifest) ([]byte, error) {
	if e := m.Validate(); e != nil {
		return nil, e
	}
	b, e := json.Marshal(m)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(b)
	out := append([]byte(`{"manifest":`), b...)
	out = append(out, []byte(fmt.Sprintf(",\"manifest_sha256\":\"%x\"}\n", h))...)
	return out, nil
}

// DecodeCurrent は復号後の再整形をせず、元byteのチェックサムを検査する。
func DecodeCurrent(b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > 16<<10 {
		return m, ErrCorrupt
	}
	var e currentEnvelope
	if err := strictjson.Decode(b, &e); err != nil {
		return m, err
	}
	if sha256.Sum256(e.Manifest) != e.SHA {
		return m, ErrCorrupt
	}
	if err := strictjson.Decode(e.Manifest, &m); err != nil {
		return m, err
	}
	return m, m.Validate()
}
func (m Manifest) Validate() error {
	if m.Schema != 1 || m.BoardID == (domain.ID{}) || m.ThreadKey == 0 || m.Generation == 0 || m.Delta.File != fmt.Sprintf("delta-%06d.wal", m.Generation) || m.Delta.RequiredEnd < 64 {
		return ErrCorrupt
	}
	d := m.Delta
	if m.Base == nil {
		if d.BaseSeq != 0 || d.RequiredSeq == 0 || d.RequiredEnd <= 64 {
			return ErrCorrupt
		}
	} else {
		b := m.Base
		if b.File != fmt.Sprintf("base-%06d.pack", m.Generation) || b.Seq == 0 || b.Length == 0 || b.DATGeneration == 0 || b.Seq != d.BaseSeq || d.RequiredSeq < d.BaseSeq {
			return ErrCorrupt
		}
		if (d.RequiredSeq == d.BaseSeq) != (d.RequiredEnd == 64) {
			return ErrCorrupt
		}
	}
	return nil
}

// Scan はヘッダと必須確定位置を照合し、各完全フレームを順に検証する。
// validateは候補状態だけを変更し、Scan成功まで公開してはならない。
func Scan(r io.Reader, want Header, required Delta, validate func(Frame) error) (validEnd int64, incomplete bool, err error) {
	hb := make([]byte, 64)
	if _, err = io.ReadFull(r, hb); err != nil {
		return 0, false, err
	}
	h, e := DecodeHeader(hb)
	if e != nil || h != want {
		return 0, false, ErrCorrupt
	}
	hasher := sha256.New()
	_, _ = hasher.Write(hb)
	validEnd = 64
	seq := h.BaseSeq
	matched := false
	check := func() error {
		if uint64(validEnd) != uint64(required.RequiredEnd) {
			return nil
		}
		if seq != uint64(required.RequiredSeq) || !bytes.Equal(hasher.Sum(nil), required.RequiredSHA[:]) {
			return ErrCorrupt
		}
		matched = true
		return nil
	}
	if e = check(); e != nil {
		return 0, false, e
	}
	for {
		f, size, e := ReadFrame(io.TeeReader(r, hasher))
		if e == io.EOF || e == ErrIncomplete {
			if !matched {
				return 0, false, ErrCorrupt
			}
			return validEnd, e == ErrIncomplete, nil
		}
		if e != nil {
			return 0, false, e
		}
		if seq == ^uint64(0) || f.FirstSeq != seq+1 {
			return 0, false, ErrCorrupt
		}
		if h.Kind != 0 && (len(f.Records) != 1 || len(f.Records[0].DAT) != 0) {
			return 0, false, ErrCorrupt
		}
		if validate != nil {
			if e = validate(f); e != nil {
				return 0, false, e
			}
		}
		seq = f.FirstSeq + uint64(len(f.Records)) - 1
		validEnd += size
		if e = check(); e != nil {
			return 0, false, e
		}
		if !matched && uint64(validEnd) > uint64(required.RequiredEnd) {
			return 0, false, ErrCorrupt
		}
	}
}
