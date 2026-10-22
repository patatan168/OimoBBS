// 署名sourceのJSON受理条件を従来の完全コピーによる復号と照合する。
package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

// referenceSource は最適化前のmap復号と必須項目・値の検査を再現する。
func referenceSource(raw []byte, source Source) bool {
	if len(raw) > 512<<10 || source.Owner == (domain.ID{}) || source.Seq == 0 || strictjson.Validate(raw) != nil {
		return false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	var owner domain.ID
	var day, seq domain.U64
	return json.Unmarshal(obj["source_owner_id"], &owner) == nil && json.Unmarshal(obj["source_subkey"], &day) == nil && json.Unmarshal(obj["source_control_seq"], &seq) == nil && owner == source.Owner && uint64(day) == source.Subkey && uint64(seq) == source.Seq
}

func FuzzSourceEquivalence(f *testing.F) {
	source := Source{domain.ID{1}, 0, 1}
	good := fmt.Sprintf(`{"source_owner_id":"%s","source_subkey":"0","source_control_seq":"1","extra":{"v":"ignored"}}`, source.Owner)
	for _, raw := range []string{good, strings.Replace(good, "source_owner_id", "SOURCE_OWNER_ID", 1), strings.Replace(good, `"source_subkey":"0",`, "", 1), strings.Replace(good, `"source_subkey":"0"`, `"source_subkey":null`, 1), strings.Replace(good, "source_subkey", `source_\u0073ubkey`, 1), strings.Replace(good, `"source_subkey":"0"`, `"source_subkey":"0","source_\u0073ubkey":"0"`, 1), `null`, `{}`, `[]`, strings.Replace(good, `"extra":{"v":"ignored"}`, `"extra":"`+strings.Repeat("x", 16384)+`"`, 1)} {
		f.Add([]byte(raw), uint64(0))
	}
	f.Fuzz(func(t *testing.T, raw []byte, day uint64) {
		src := source
		src.Subkey = day
		if (validSource(raw, src) == nil) != referenceSource(raw, src) {
			t.Fatalf("source acceptance differs: %q day=%d", raw, day)
		}
	})
}

func BenchmarkEvidenceSource(b *testing.B) {
	source := Source{domain.ID{1}, 20261016, 1}
	for _, size := range []int{4096, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			raw := []byte(fmt.Sprintf(`{"source_owner_id":"%s","source_subkey":"20261016","source_control_seq":"1","content":"%s"}`, source.Owner, strings.Repeat("x", size)))
			b.ReportAllocs()
			for b.Loop() {
				if err := validSource(raw, source); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
