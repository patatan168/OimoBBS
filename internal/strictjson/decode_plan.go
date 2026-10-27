// 復号する保存型の構造だけを共有し、JSON本文・復号先・可変の検査状態は保持しない。
package strictjson

import (
	"encoding"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
)

type decodeField struct {
	index int
	plan  *decodePlan
}

type decodePlan struct {
	typ      reflect.Type
	fields   map[string]decodeField
	elem     *decodePlan
	custom   bool
	eligible bool
}

var decodePlans sync.Map

// planFor は型グラフ全体の構築後だけ公開し、再帰型にも未完成の共有情報を渡さない。
func planFor(t reflect.Type) *decodePlan {
	if cached, ok := decodePlans.Load(t); ok {
		return cached.(*decodePlan)
	}
	plan := buildDecodePlan(t, make(map[reflect.Type]*decodePlan))
	plan.eligible = plan.usable(make(map[*decodePlan]bool))
	cached, _ := decodePlans.LoadOrStore(t, plan)
	return cached.(*decodePlan)
}

func buildDecodePlan(t reflect.Type, building map[reflect.Type]*decodePlan) *decodePlan {
	if prior := building[t]; prior != nil {
		return prior
	}
	p := &decodePlan{typ: t, eligible: true}
	building[t] = p
	if _, ok := reflect.PointerTo(t).MethodByName("UnmarshalJSONFrom"); ok {
		p.eligible = false
		return p
	}
	if t == rawType {
		return p
	}
	if t.Kind() == reflect.Pointer {
		p.elem = buildDecodePlan(t.Elem(), building)
		return p
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		p.custom = true
		return p
	}
	if reflect.PointerTo(t).Implements(reflect.TypeFor[encoding.TextUnmarshaler]()) || t == reflect.TypeFor[json.Number]() {
		p.eligible = false
		return p
	}
	switch t.Kind() {
	case reflect.Struct:
		p.fields = make(map[string]decodeField, t.NumField())
		for i := range t.NumField() {
			field := t.Field(i)
			name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			// string等の表現指定、非公開field、特殊な埋込みは標準復号経路へ残す。
			if name == "" || name == "-" || field.PkgPath != "" || options != "" && options != "omitempty" {
				p.eligible = false
				continue
			}
			if _, ok := p.fields[name]; ok {
				p.eligible = false
				continue
			}
			p.fields[name] = decodeField{i, buildDecodePlan(field.Type, building)}
		}
	case reflect.Array, reflect.Slice:
		p.elem = buildDecodePlan(t.Elem(), building)
	}
	return p
}

// usable は循環を一度だけ辿り、特殊なタグを持つ子型も標準経路へ残す。
func (p *decodePlan) usable(seen map[*decodePlan]bool) bool {
	if seen[p] {
		return true
	}
	seen[p] = true
	if !p.eligible {
		return false
	}
	if p.elem != nil && !p.elem.usable(seen) {
		return false
	}
	for _, f := range p.fields {
		if !f.plan.usable(seen) {
			return false
		}
	}
	return true
}
