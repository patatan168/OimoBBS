// 固定保存型の生成復号器から反射なしで値を読み、共通の厳密JSON検査を維持する。
package strictjson

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strconv"
	"unicode/utf8"
)

// GeneratedDecoder は純粋な保存型専用の生成復号器。失敗時は宛先を変更しない。
// handled=falseでは宛先を変更せず、既存値のmergeや大きな本文を汎用経路へ戻す。
// 独自UnmarshalJSON等の任意callbackを先行実行する用途には使わない。
type GeneratedDecoder interface {
	UnmarshalStrictJSON(body []byte, limit int) (handled bool, err error)
	StrictJSONType() reflect.Type
}

// TypedReader は一回の私的候補だけに使う。最初のエラーを保持し、Finish前に値を公開しない。
// 構文・深さ・Unicodeは共通scannerを使い、固定キー集合は生成コードが照合する。
type TypedReader struct {
	checkedScanner
	depth int
	err   error
}

// NewTypedReader は通常のDecodeLimitと同じサイズ・UTF-8・最上位object条件を検査する。
func NewTypedReader(body []byte, limit int) TypedReader {
	r := TypedReader{checkedScanner: checkedScanner{keyScanner: keyScanner{body: body}, strict: true}}
	if limit < 0 || limit > 8<<20 || len(body) > limit || !utf8.Valid(body) {
		r.err = errSyntax
		return r
	}
	r.space()
	if r.pos == len(body) || body[r.pos] != '{' {
		r.err = errSyntax
	}
	return r
}

// Reject は固定キー・必須項目・独自保存型の制約違反を記録する。
func (r *TypedReader) Reject() {
	if r.err == nil {
		r.err = errSyntax
	}
}

// Require は生成コードの必須キー集合を照合し、先行エラーを維持する。
func (r *TypedReader) Require(ok bool) {
	if !ok {
		r.Reject()
	}
}

// Finish は全階層の閉じ括弧と本文末尾を検査し、成功後だけ候補の公開を許す。
func (r *TypedReader) Finish() error {
	r.space()
	if r.depth != 0 || r.pos != len(r.body) {
		r.Reject()
	}
	return r.err
}

// TypedIterator はobject/arrayの区切りだけを管理する。Keyは次のNextまでの借用値。
type TypedIterator struct {
	r     *TypedReader
	Key   []byte
	close byte
	first bool
}

func (r *TypedReader) container(open, close byte) TypedIterator {
	r.space()
	if r.err == nil {
		if r.depth == 16 || r.pos == len(r.body) || r.body[r.pos] != open {
			r.Reject()
		} else {
			r.pos++
			r.depth++
		}
	}
	return TypedIterator{r: r, close: close, first: true}
}

// Object は深さを一段進める。全項目の読み取り後までNextを呼ぶ。
func (r *TypedReader) Object() TypedIterator { return r.container('{', '}') }

// Array はnullを拒否し、深さを一段進める。nil許可はポインタ側のNullで表す。
func (r *TypedReader) Array() TypedIterator { return r.container('[', ']') }

// Next はcomma・colon・末尾commaを検査し、次の値またはキーを用意する。
func (it *TypedIterator) Next() bool {
	r := it.r
	if r.err != nil {
		return false
	}
	r.space()
	if r.pos == len(r.body) {
		r.Reject()
		return false
	}
	if r.body[r.pos] == it.close {
		r.pos++
		r.depth--
		return false
	}
	if !it.first {
		if r.body[r.pos] != ',' {
			r.Reject()
			return false
		}
		r.pos++
		r.space()
		if r.pos == len(r.body) || r.body[r.pos] == it.close {
			r.Reject()
			return false
		}
	}
	it.first = false
	if it.close == '}' {
		it.Key, r.err = r.checkedString(true)
		if r.err != nil {
			return false
		}
		r.space()
		if r.pos == len(r.body) || r.body[r.pos] != ':' {
			r.Reject()
			return false
		}
		r.pos++
	}
	return true
}

// Null はnullableポインタのnullだけを消費する。その他の値は進めない。
func (r *TypedReader) Null() bool {
	if r.err != nil {
		return false
	}
	r.space()
	if bytes.HasPrefix(r.body[r.pos:], []byte("null")) {
		r.pos += 4
		return true
	}
	return false
}

func (r *TypedReader) text() []byte {
	if r.err != nil {
		return nil
	}
	r.space()
	var value []byte
	value, r.err = r.checkedString(true)
	return value
}

// String は借用せずに文字列を復号する。NUL・不正surrogate・nullは拒否する。
func (r *TypedReader) String() string { return string(r.text()) }

// Bool はtrue/falseだけを読む。
func (r *TypedReader) Bool() bool {
	if r.err != nil {
		return false
	}
	r.space()
	if bytes.HasPrefix(r.body[r.pos:], []byte("true")) {
		r.pos += 4
		return true
	}
	if bytes.HasPrefix(r.body[r.pos:], []byte("false")) {
		r.pos += 5
		return false
	}
	r.Reject()
	return false
}

func (r *TypedReader) number() []byte {
	if r.err != nil {
		return nil
	}
	r.space()
	start := r.pos
	if start == len(r.body) {
		r.Reject()
		return nil
	}
	r.err = r.checkedNumber()
	value := r.body[start:r.pos]
	if bytes.ContainsAny(value, ".eE+") || bytes.Equal(value, []byte("-0")) {
		r.Reject()
	}
	return value
}

// Uint はJSON数値の正規表記と指定bit幅の符号なし整数を照合する。
func (r *TypedReader) Uint(bits int) uint64 {
	raw := r.number()
	if r.err != nil {
		return 0
	}
	v, err := strconv.ParseUint(string(raw), 10, bits)
	if err != nil {
		r.Reject()
	}
	return v
}

// Int はJSON数値の正規表記と指定bit幅の符号付き整数を照合する。
func (r *TypedReader) Int(bits int) int64 {
	raw := r.number()
	if r.err != nil {
		return 0
	}
	v, err := strconv.ParseInt(string(raw), 10, bits)
	if err != nil {
		r.Reject()
	}
	return v
}

func decimal(text []byte, signed bool) bool {
	if len(text) == 0 {
		return false
	}
	if signed && text[0] == '-' {
		text = text[1:]
		if len(text) == 0 || text[0] == '0' {
			return false
		}
	}
	return text[0] >= '0' && text[0] <= '9' && (len(text) == 1 || text[0] != '0')
}

// UintString はdomain.U64と同じ正規十進文字列を読む。Unicode escapeも同じ値へ復号する。
func (r *TypedReader) UintString() uint64 {
	raw := r.text()
	if r.err != nil {
		return 0
	}
	v, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil || !decimal(raw, false) {
		r.Reject()
	}
	return v
}

// IntString はdomain.Timeと同じ正規十進文字列を読む。
func (r *TypedReader) IntString() int64 {
	raw := r.text()
	if r.err != nil {
		return 0
	}
	v, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || !decimal(raw, true) {
		r.Reject()
	}
	return v
}

// Hex は小文字hex文字列を固定長領域へ復号する。id=trueでは全ゼロを拒否する。
func (r *TypedReader) Hex(dst []byte, id bool) {
	raw := r.text()
	if r.err != nil {
		return
	}
	if len(raw) != hex.EncodedLen(len(dst)) {
		r.Reject()
		return
	}
	for _, c := range raw {
		if c >= 'A' && c <= 'F' {
			r.Reject()
			return
		}
	}
	if _, err := hex.Decode(dst, raw); err != nil {
		r.Reject()
		return
	}
	if id {
		var nonzero byte
		for _, c := range dst {
			nonzero |= c
		}
		if nonzero == 0 {
			r.Reject()
		}
	}
}

// Raw は任意JSONにも重複キー・深さ・Unicodeを照合し、元byteを複製する。
func (r *TypedReader) Raw() []byte {
	if r.err != nil {
		return nil
	}
	r.space()
	start := r.pos
	r.err = r.checkedValue(r.depth)
	if r.err != nil {
		return nil
	}
	return bytes.Clone(r.body[start:r.pos])
}
