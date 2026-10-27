// Package jsonencode は固定保存DTOの生成コードから、反射なしで既存JSON表記を組み立てる。
package jsonencode

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
)

// Writer は一回の符号化に閉じた作業領域。BoundOnlyでは安全なサイズ上界だけを数える。
// Limit超過後も入力の値検査を維持し、サイズ計算の整数overflowを防ぐ。
type Writer struct {
	Bytes     []byte
	Err       error
	BoundOnly bool
	Limit     int
	Size      int
	serial    bool
}

// ErrBoundLimit は生成コードが扱える0〜8MiB以外の上限を拒否する。
var ErrBoundLimit = errors.New("JSON bound limit")

// ErrZeroID は標準保存型と同じ全ゼロIDの拒否を表す。
var ErrZeroID = errors.New("zero ID")

// add はサイズ上界をLimit+1で飽和させる。BoundOnly専用。
func (w *Writer) add(n int) {
	if n > w.Limit-w.Size {
		w.Size = w.Limit + 1
		return
	}
	w.Size += n
}

// Literal は生成器が固定したJSON構造とキーだけを挿入する。
func (w *Writer) Literal(s string) {
	if w.BoundOnly {
		w.add(len(s))
		return
	}
	w.Bytes = append(w.Bytes, s...)
}

// String は標準Marshalと同じHTML・JavaScript escapeとUTF-8置換を使う。
func (w *Writer) String(s string) {
	if w.BoundOnly {
		if len(s) > (w.Limit-w.Size-2)/6 {
			w.Size = w.Limit + 1
			return
		}
		w.add(6*len(s) + 2)
		return
	}
	w.Bytes = AppendString(w.Bytes, s)
}

// Uint は通常数値、quoted=trueではdomain.U64と同じ正規十進文字列を生成する。
func (w *Writer) Uint(v uint64, quoted bool) {
	if w.BoundOnly {
		w.add(22)
		return
	}
	if quoted {
		w.Bytes = append(w.Bytes, '"')
	}
	w.Bytes = strconv.AppendUint(w.Bytes, v, 10)
	if quoted {
		w.Bytes = append(w.Bytes, '"')
	}
}

// Int は通常数値、quoted=trueではdomain.Timeと同じ正規十進文字列を生成する。
func (w *Writer) Int(v int64, quoted bool) {
	if w.BoundOnly {
		w.add(22)
		return
	}
	if quoted {
		w.Bytes = append(w.Bytes, '"')
	}
	w.Bytes = strconv.AppendInt(w.Bytes, v, 10)
	if quoted {
		w.Bytes = append(w.Bytes, '"')
	}
}

// Bool は既存のtrue/false表記を生成する。
func (w *Writer) Bool(v bool) {
	if v {
		w.Literal("true")
	} else {
		w.Literal("false")
	}
}

// Hex はID/Hashだけに使い、IDの全ゼロ拒否も標準Marshalと同じく保つ。
func (w *Writer) Hex(raw []byte, id bool) {
	if id {
		var nonzero byte
		for _, b := range raw {
			nonzero |= b
		}
		if nonzero == 0 {
			w.Err = ErrZeroID
		}
	}
	if w.BoundOnly {
		w.add(2 + hex.EncodedLen(len(raw)))
		return
	}
	w.Bytes = append(w.Bytes, '"')
	w.Bytes = hex.AppendEncode(w.Bytes, raw)
	w.Bytes = append(w.Bytes, '"')
}

// Raw は任意RawMessageの構文・compact・HTML escapeを標準処理で維持する。
// JSON入力を信頼済みとして無検査で挿入する経路は作らない。
func (w *Writer) Raw(raw json.RawMessage) {
	b, err := json.Marshal(raw)
	if err != nil {
		w.Err = err
		return
	}
	if w.BoundOnly {
		w.add(len(b))
		return
	}
	w.Bytes = append(w.Bytes, b...)
}
