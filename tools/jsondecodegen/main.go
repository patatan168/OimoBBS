// 投稿の固定保存型から、反射を使わない厳密JSON復号コードを生成する。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

type target struct {
	pkg   string
	roots []reflect.Type
}
type generator struct {
	target
	types    []reflect.Type
	seen     map[reflect.Type]bool
	imports  map[string]bool
	out      bytes.Buffer
	variable int
}

var rawType = reflect.TypeFor[json.RawMessage]()
var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

func targets() []target {
	return []target{
		{"domain", []reflect.Type{reflect.TypeFor[domain.Operation](), reflect.TypeFor[domain.Append](), reflect.TypeFor[domain.Create]()}},
		{"evidence", []reflect.Type{reflect.TypeFor[evidence.HTTPObservation](), reflect.TypeFor[evidence.Event](), reflect.TypeFor[evidence.OptionalRecord](), reflect.TypeFor[evidence.OptionalPayload]()}},
		{"postcapture", []reflect.Type{reflect.TypeFor[postcapture.Capture]()}},
		{"store", []reflect.Type{reflect.TypeFor[store.ControlOperation]()}},
	}
}

func main() {
	check := flag.Bool("check", false, "保存型からの生成一致だけを検査する")
	flag.Parse()
	if err := generateAll(".", *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generateAll(root string, check bool) error {
	for _, t := range targets() {
		g := generator{target: t, seen: map[reflect.Type]bool{}, imports: map[string]bool{}}
		src := g.generate()
		path := filepath.Join(root, "internal", t.pkg, "json_decode_generated.go")
		if check {
			old, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(old, src) {
				return fmt.Errorf("stale generated decoder: %s", path)
			}
		} else if err := os.WriteFile(path, src, 0644); err != nil {
			return err
		}
	}
	return nil
}

func scalar(t reflect.Type) bool {
	return t == rawType || t.PkgPath() == "oimobbs/internal/domain" && (t.Name() == "ID" || t.Name() == "Hash" || t.Name() == "U64" || t.Name() == "Time")
}

// optionalCapOnly は純粋な既存復号器の省略可能boolだけを明示する。
// 他の独自復号器を構造から推測して迂回しない。対応外の追加時は生成を拒否する。
func optionalCapOnly(t reflect.Type) bool {
	return t.PkgPath() == "oimobbs/internal/domain" && t.Name() == "Policy" || t.PkgPath() == "oimobbs/internal/postinput" && t.Name() == "Input"
}

func (g *generator) name(t reflect.Type) string {
	if t.PkgPath() == "" {
		return t.String()
	}
	if t.PkgPath() == "oimobbs/internal/"+g.pkg {
		return t.Name()
	}
	g.imports[t.PkgPath()] = true
	return filepath.Base(t.PkgPath()) + "." + t.Name()
}
func reader(t reflect.Type) string {
	pkg := filepath.Base(t.PkgPath())
	return "readStrict" + strings.ToUpper(pkg[:1]) + pkg[1:] + t.Name()
}
func (g *generator) line(indent int, s string, args ...any) {
	g.out.WriteString(strings.Repeat("\t", indent))
	fmt.Fprintf(&g.out, s, args...)
	g.out.WriteByte('\n')
}
func (g *generator) next() string { g.variable++; return fmt.Sprintf("local%d", g.variable) }

func (g *generator) collect(t reflect.Type) {
	if scalar(t) {
		return
	}
	if t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		g.collect(t.Elem())
		return
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) && !optionalCapOnly(t) {
		panic("unsupported callback: " + t.String())
	}
	switch t.Kind() {
	case reflect.Struct:
		if g.seen[t] {
			return
		}
		g.seen[t] = true
		if t.NumField() > 64 || t.Name() == "" {
			panic("unsupported struct: " + t.String())
		}
		g.types = append(g.types, t)
		for i := 0; i < t.NumField(); i++ {
			g.collect(t.Field(i).Type)
		}
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	default:
		panic("unsupported type: " + t.String())
	}
}

func (g *generator) value(indent int, expr string, t reflect.Type) {
	if t == rawType {
		g.line(indent, "%s = r.Raw()", expr)
		return
	}
	if scalar(t) {
		switch t.Name() {
		case "U64":
			g.line(indent, "%s = %s(r.UintString())", expr, g.name(t))
		case "Time":
			g.line(indent, "%s = %s(r.IntString())", expr, g.name(t))
		case "ID", "Hash":
			g.line(indent, "r.Hex((%s)[:],%t)", expr, t.Name() == "ID")
		}
		return
	}
	switch t.Kind() {
	case reflect.Pointer:
		g.line(indent, "if !r.Null() {")
		g.line(indent+1, "%s = new(%s)", expr, g.name(t.Elem()))
		g.value(indent+1, "(*("+expr+"))", t.Elem())
		g.line(indent, "}")
	case reflect.Struct:
		g.line(indent, "%s(r,&(%s))", reader(t), expr)
	case reflect.Slice:
		it := g.next()
		element := g.next()
		g.line(indent, "%s := r.Array()", it)
		g.line(indent, "%s = make([]%s,0)", expr, g.name(t.Elem()))
		g.line(indent, "for %s.Next() {", it)
		g.line(indent+1, "var %s %s", element, g.name(t.Elem()))
		g.value(indent+1, element, t.Elem())
		g.line(indent+1, "%s = append(%s,%s)", expr, expr, element)
		g.line(indent, "}")
	case reflect.String:
		g.line(indent, "%s = %s(r.String())", expr, g.name(t))
	case reflect.Bool:
		g.line(indent, "%s = %s(r.Bool())", expr, g.name(t))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		g.line(indent, "%s = %s(r.Int(%d))", expr, g.name(t), t.Bits())
	default:
		g.line(indent, "%s = %s(r.Uint(%d))", expr, g.name(t), t.Bits())
	}
}

func (g *generator) structure(t reflect.Type) {
	g.line(0, "// %s は%sの完全キー集合と値を私的候補へ復号する。", reader(t), t.Name())
	g.line(0, "func %s(r *strictjson.TypedReader,v *%s) {", reader(t), g.name(t))
	g.line(1, "object := r.Object()")
	g.line(1, "var seen uint64")
	g.line(1, "for object.Next() {")
	g.line(2, "var bit uint64")
	g.line(2, "switch string(object.Key) {")
	mask := uint64(0)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		key, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if f.PkgPath != "" || key == "" || key == "-" || opts != "" && opts != "omitempty" {
			panic("unsupported field: " + t.String() + "." + f.Name)
		}
		bit := uint64(1) << i
		if !(key == "cap_only" && optionalCapOnly(t)) {
			mask |= bit
		}
		g.line(2, "case %s:", strconv.Quote(key))
		g.line(3, "bit = %d", bit)
	}
	g.line(2, "default: r.Reject(); return")
	g.line(2, "}")
	g.line(2, "if seen&bit!=0 { r.Reject(); return }")
	g.line(2, "seen |= bit")
	g.line(2, "switch bit {")
	for i := 0; i < t.NumField(); i++ {
		g.line(2, "case %d:", uint64(1)<<i)
		g.value(3, "v."+t.Field(i).Name, t.Field(i).Type)
	}
	g.line(2, "}")
	g.line(1, "}")
	g.line(1, "r.Require(seen&%d==%d)", mask, mask)
	g.line(0, "}")
}

func (g *generator) generate() []byte {
	for _, t := range g.roots {
		g.collect(t)
	}
	for _, t := range g.roots {
		g.line(0, "// StrictJSONType は埋込みによるmethod昇格を区別し、この保存型だけへ専用復号を適用する。")
		g.line(0, "func (*%s) StrictJSONType() reflect.Type { return reflect.TypeFor[*%s]() }", t.Name(), t.Name())
		g.line(0, "// UnmarshalStrictJSON はゼロ値の%sを反射なしで復号し、全検査成功後だけ公開する。", t.Name())
		g.line(0, "// 128KiB以上・既存値のmerge・nil宛先は従来経路へ戻す。保存形式や業務制約は変更しない。")
		g.line(0, "func (v *%s) UnmarshalStrictJSON(body []byte,limit int) (bool,error) {", t.Name())
		g.line(1, "if v==nil || len(body)>=128<<10 || !reflect.ValueOf(v).Elem().IsZero() { return false,nil }")
		g.line(1, "var candidate %s", t.Name())
		g.line(1, "r := strictjson.NewTypedReader(body,limit)")
		g.line(1, "%s(&r,&candidate)", reader(t))
		g.line(1, "if err:=r.Finish();err!=nil { return true,err }")
		g.line(1, "*v = candidate")
		g.line(1, "return true,nil")
		g.line(0, "}")
	}
	for _, t := range g.types {
		g.structure(t)
	}
	var header bytes.Buffer
	fmt.Fprintf(&header, "// Code generated by tools/jsondecodegen; DO NOT EDIT.\n// 固定保存型の構文・完全キー集合・Unicode・値域を一度で照合する。\npackage %s\n\nimport (\n\"reflect\"\n\"oimobbs/internal/strictjson\"\n", g.pkg)
	imports := make([]string, 0, len(g.imports))
	for p := range g.imports {
		imports = append(imports, p)
	}
	sort.Strings(imports)
	for _, p := range imports {
		fmt.Fprintf(&header, "%q\n", p)
	}
	header.WriteString(")\n\n")
	header.Write(g.out.Bytes())
	src, err := format.Source(header.Bytes())
	if err != nil {
		panic(err)
	}
	return src
}
