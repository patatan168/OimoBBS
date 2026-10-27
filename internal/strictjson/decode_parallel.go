// 一件の大きな配列を要素境界で分け、型検査と復号を私的な出力領域で処理する。
package strictjson

import (
	"oimobbs/internal/parallel"
	"reflect"
)

type arrayDecodeSpan struct {
	start, end  int
	first, last int
	decoder     *checkedDecoder
	err         error
}

// arrayLayout は従来必要だったslice長の走査で、最大CPU数までのbyte境界も集める。
// 分担候補では重複キー検査を型付き走査へまとめる。構文・深さ・Unicodeは先に検査する。
func (d *checkedDecoder) arrayLayout() (int, []arrayDecodeSpan, error) {
	s := d.checkedScanner
	if s.pos < len(s.body) && s.body[s.pos] == ']' {
		return 0, nil, nil
	}
	workers := min(d.workers, (len(s.body)-s.pos)/(64<<10))
	var spans []arrayDecodeSpan
	target := len(s.body)
	if workers > 1 {
		s.strict = false
		target = (len(s.body) - s.pos) / workers
	}
	start, first, count := s.pos, 0, 0
	for {
		if err := s.checkedValue(d.depth); err != nil {
			return 0, nil, err
		}
		count++
		end, err := s.separator(']')
		if err != nil {
			return 0, nil, err
		}
		if workers > 1 && (end && len(spans) > 0 || !end && len(spans) < workers-1 && s.pos-start >= target) {
			if spans == nil {
				spans = make([]arrayDecodeSpan, 0, workers)
			}
			spans = append(spans, arrayDecodeSpan{start: start, end: s.pos, first: first, last: count})
			start, first = s.pos, count
		}
		if end {
			if count < 128 || s.pos-d.pos < 128<<10 {
				spans = nil
			}
			return count, spans, nil
		}
	}
}

// decodeArrayParallel は出力先を要素ごとに分離し、全検査成功まで独自復号を実行しない。
// 保留した復号は元の順番で親へ戻し、本文末尾の不正で副作用が発生することを防ぐ。
func (d *checkedDecoder) decodeArrayParallel(p *decodePlan, v reflect.Value, spans []arrayDecodeSpan) (bool, error) {
	body, depth := d.body, d.depth
	if !parallel.TryCPU(len(spans), func(i int) {
		span := &spans[i]
		child := &checkedDecoder{
			checkedScanner: checkedScanner{keyScanner: keyScanner{body: body, pos: span.start}, strict: true},
			depth:          depth, defaultIndex: -1,
		}
		span.decoder = child
		for j := span.first; j < span.last; j++ {
			if span.err = child.value(p.elem, v.Index(j)); span.err != nil {
				return
			}
			end, err := child.separator(']')
			if err != nil || end != (j+1 == v.Len()) {
				span.err = errSyntax
				return
			}
		}
		if child.pos != span.end {
			span.err = errSyntax
		}
	}) {
		return false, nil
	}
	for i := range spans {
		span := &spans[i]
		if span.err != nil {
			return true, span.err
		}
		if span.decoder.count > 0 {
			d.groups = append(d.groups, decodeActionGroup{before: d.count, decoder: span.decoder})
		}
	}
	d.pos = spans[len(spans)-1].end
	return true, nil
}
