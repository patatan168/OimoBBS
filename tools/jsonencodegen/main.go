// 固定保存DTOの定義を読み、反射を使わないJSON符号化コードを再生成する。
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
)

type target struct {
	path, pkg string
	roots     []reflect.Type
	capacity  int
}
type generator struct {
	target
	types   []reflect.Type
	seen    map[reflect.Type]bool
	imports map[string]bool
	out     bytes.Buffer
	check   bool
}

var rawType = reflect.TypeFor[json.RawMessage]()
var checkGenerated = flag.Bool("check", false, "生成コードの一致だけを検査する")

func main() {
	flag.Parse()
	for _, t := range configuredTargets() {
		g := generator{target: t, check: *checkGenerated, seen: map[reflect.Type]bool{}, imports: map[string]bool{}}
		g.generate()
	}
}

// configuredTargets は実際の保存経路に使う型だけを生成対象へ固定する。
func configuredTargets() []target {
	return []target{
		{"internal/evidence/json_generated.go", "evidence", []reflect.Type{reflect.TypeFor[evidence.HTTPObservation](), reflect.TypeFor[evidence.OptionalRecord](), reflect.TypeFor[evidence.OptionalPayload]()}, 2048},
		{"internal/postcapture/json_generated.go", "postcapture", []reflect.Type{reflect.TypeFor[postcapture.Capture]()}, 4096},
		{"internal/domain/json_generated.go", "domain", []reflect.Type{reflect.TypeFor[domain.Append](), reflect.TypeFor[domain.Create](), reflect.TypeFor[domain.Operation]()}, 2048},
	}
}

func scalar(t reflect.Type) bool {
	return t.PkgPath() == "oimobbs/internal/domain" && (t.Name() == "ID" || t.Name() == "Hash" || t.Name() == "U64" || t.Name() == "Time") || t == rawType
}
func (g *generator) typeName(t reflect.Type) string {
	if filepath.Base(t.PkgPath()) == g.pkg {
		return t.Name()
	}
	if t.PkgPath() == "" {
		return t.String()
	}
	g.imports[t.PkgPath()] = true
	return filepath.Base(t.PkgPath()) + "." + t.Name()
}
func function(t reflect.Type) string {
	pkg := filepath.Base(t.PkgPath())
	return "appendJSON" + strings.ToUpper(pkg[:1]) + pkg[1:] + t.Name()
}
func (g *generator) collect(t reflect.Type) {
	if scalar(t) {
		return
	}
	if t.Kind() == reflect.Pointer {
		g.collect(t.Elem())
		return
	}
	if t.Implements(reflect.TypeFor[json.Marshaler]()) || reflect.PointerTo(t).Implements(reflect.TypeFor[json.Marshaler]()) {
		panic("unsupported custom JSON type: " + t.String())
	}
	if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
		panic("byte slice requires base64 support: " + t.String())
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		g.collect(t.Elem())
	case reflect.Struct:
		if g.seen[t] {
			return
		}
		g.seen[t] = true
		g.types = append(g.types, t)
		if t.Name() == "" {
			panic("anonymous JSON structure")
		}
		for i := 0; i < t.NumField(); i++ {
			g.collect(t.Field(i).Type)
		}
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	default:
		panic("unsupported JSON type: " + t.String())
	}
}
func (g *generator) line(indent int, s string, args ...any) {
	g.out.WriteString(strings.Repeat("\t", indent))
	fmt.Fprintf(&g.out, s, args...)
	g.out.WriteByte('\n')
}
func (g *generator) literal(indent int, s string) { g.line(indent, "w.Literal(%s)", strconv.Quote(s)) }
func (g *generator) value(indent int, expr string, t reflect.Type) {
	if t == rawType {
		g.line(indent, "w.Raw(%s)", expr)
		return
	}
	if scalar(t) {
		switch t.Name() {
		case "ID", "Hash":
			g.line(indent, "w.Hex((%s)[:], %t)", expr, t.Name() == "ID")
		case "U64":
			g.line(indent, "w.Uint(uint64(%s), true)", expr)
		case "Time":
			g.line(indent, "w.Int(int64(%s), true)", expr)
		case "RawMessage":
			g.line(indent, "w.Raw(%s)", expr)
		}
		return
	}
	switch t.Kind() {
	case reflect.Pointer:
		g.line(indent, "if %s == nil {", expr)
		g.literal(indent+1, "null")
		g.line(indent, "} else {")
		g.value(indent+1, "(*("+expr+"))", t.Elem())
		g.line(indent, "}")
	case reflect.Struct:
		g.line(indent, "%s(w, %s)", function(t), expr)
	case reflect.Slice, reflect.Array:
		if t.Kind() == reflect.Slice {
			g.line(indent, "if %s == nil {", expr)
			g.literal(indent+1, "null")
			g.line(indent, "} else {")
			indent++
		}
		g.literal(indent, "[")
		if t.Kind() == reflect.Slice {
			g.line(indent, "if !w.CanParallelArray(len(%s)) || !jsonencode.TryArray(w, len(%s), func(w *jsonencode.Writer, start, end int) {", expr, expr)
			g.line(indent+1, "for i := start; i < end; i++ {")
			g.line(indent+2, "if i > start {")
			g.literal(indent+3, ",")
			g.line(indent+2, "}")
			g.value(indent+2, "("+expr+")[i]", t.Elem())
			g.line(indent+1, "}")
			g.line(indent, "}) {")
			indent++
		}
		g.line(indent, "for i := range %s {", expr)
		g.line(indent+1, "if i > 0 {")
		g.literal(indent+2, ",")
		g.line(indent+1, "}")
		g.value(indent+1, "("+expr+")[i]", t.Elem())
		g.line(indent, "}")
		if t.Kind() == reflect.Slice {
			indent--
			g.line(indent, "}")
		}
		g.literal(indent, "]")
		if t.Kind() == reflect.Slice {
			indent--
			g.line(indent, "}")
		}
	case reflect.String:
		g.line(indent, "w.String(%s)", expr)
	case reflect.Bool:
		g.line(indent, "w.Bool(%s)", expr)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		g.line(indent, "w.Int(int64(%s), false)", expr)
	default:
		g.line(indent, "w.Uint(uint64(%s), false)", expr)
	}
}
func (g *generator) structure(t reflect.Type) {
	g.line(0, "// %s は%sの固定フィールド順で追記する。", function(t), t.Name())
	g.line(0, "func %s(w *jsonencode.Writer, v %s) {", function(t), g.typeName(t))
	g.literal(1, "{")
	required := false
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if f.PkgPath != "" || name == "" || name == "-" || opts != "" && opts != "omitempty" {
			panic("unsupported field " + t.String() + "." + f.Name)
		}
		indent := 1
		optional := opts == "omitempty"
		if optional {
			if f.Type.Kind() != reflect.Bool {
				panic("unsupported omitempty " + f.Name)
			}
			g.line(1, "if v.%s {", f.Name)
			indent++
		}
		prefix := ""
		if required {
			prefix = ","
		}
		g.literal(indent, prefix+strconv.Quote(name)+":")
		g.value(indent, "v."+f.Name, f.Type)
		if optional {
			if !required {
				g.literal(indent, ",")
			}
			g.line(1, "}")
		} else {
			required = true
		}
	}
	if !required {
		panic("all fields optional")
	}
	g.literal(1, "}")
	g.line(0, "}")
	g.line(0, "")
}
func (g *generator) generate() {
	for _, t := range g.roots {
		g.collect(t)
	}
	for _, t := range g.roots {
		g.line(0, "// Marshal%s は固定保存型を符号化する。業務検証と保存は呼出元で行う。", t.Name())
		g.line(0, "func Marshal%s(v %s) ([]byte,error) {", t.Name(), g.typeName(t))
		g.line(1, "w := jsonencode.Writer{Bytes:make([]byte,0,%d)}", g.capacity)
		g.line(1, "%s(&w,v)", function(t))
		g.line(1, "if w.Err != nil { return nil,w.Err }")
		g.line(1, "return w.Bytes,nil")
		g.line(0, "}")
		g.line(0, "")
	}
	if g.pkg == "evidence" {
		g.line(0, "// HTTPObservationJSONBound は生成されるJSONの安全なサイズ上界をlimit+1まで数える。")
		g.line(0, "// Unicode・HTML escapeの最悪値を使うため、上界超過時は正確な符号化へ戻す。")
		g.line(0, "func HTTPObservationJSONBound(v HTTPObservation,limit int) (int,error) {")
		g.line(1, "if limit<0 || limit>8<<20 { return 0,jsonencode.ErrBoundLimit }")
		g.line(1, "w := jsonencode.Writer{BoundOnly:true,Limit:limit}")
		g.line(1, "%s(&w,v)", function(g.roots[0]))
		g.line(1, "return w.Size,w.Err")
		g.line(0, "}")
	}
	for _, t := range g.types {
		g.structure(t)
	}
	var header bytes.Buffer
	fmt.Fprintf(&header, "// Code generated by tools/jsonencodegen; DO NOT EDIT.\n// 固定保存DTOをフィールド定義から符号化する。\npackage %s\n\nimport (\n\"oimobbs/internal/jsonencode\"\n", g.pkg)
	var imports []string
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
	if g.check {
		old, e := os.ReadFile(g.path)
		if e != nil || !bytes.Equal(old, src) {
			panic("stale generated JSON: " + g.path)
		}
		return
	}
	if err = os.WriteFile(g.path, src, 0644); err != nil {
		panic(err)
	}
	fmt.Println(g.path)
}
