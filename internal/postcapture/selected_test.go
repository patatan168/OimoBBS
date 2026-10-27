// 現行captureの一回復号と従来のschema先行判別の受理・委譲・値を比較する。
package postcapture

import (
	"bytes"
	"reflect"
	"testing"
)

func referenceSelected(raw []byte) (decodedCapture, string, error) {
	schema, err := schemaOf(raw)
	if err != nil || schema != Schema {
		return decodedCapture{}, schema, err
	}
	c, err := decode(raw)
	return c, schema, err
}

func checkSelected(t testing.TB, raw []byte) {
	t.Helper()
	want, schema, oldErr := referenceSelected(raw)
	got, selected, err := decodeSelected(raw)
	if schema != selected || (oldErr == nil) != (err == nil) || !reflect.DeepEqual(want, got) {
		t.Fatalf("selection differs: schema=%q/%q err=%v/%v input=%q", schema, selected, oldErr, err, raw)
	}
}

func selectedCorpus(t testing.TB) [][]byte {
	raw, _ := metadataFixture(t)
	corpus := [][]byte{raw, nil, []byte(`{}`), []byte(`null`), []byte(`[]`),
		[]byte(`{"schema":"other","opaque":null}`), []byte(`{"Schema":"other"}`),
		[]byte(`{"schema":null}`), []byte(`{"schema":17}`), []byte(`{"schema":"http-observation-v4"}`),
		[]byte(`{"schema":"other","schema":"form-post-v8"}`),
		[]byte(`{"schema":"form-post-v8","schema":"other"}`),
		[]byte("{\"schema\":\"other\",\"opaque\":\"\xff\"}"),
		[]byte(`{"schema":"other","opaque":"\ud800"}`)}
	for _, replacement := range []string{`"Schema":`, `"\u0073chema":`, `"schema":null,"schema":`, `"unknown":0,"schema":`} {
		corpus = append(corpus, bytes.Replace(raw, []byte(`"schema":`), []byte(replacement), 1))
	}
	corpus = append(corpus, append(bytes.Clone(raw), []byte(` trailing`)...),
		bytes.Replace(raw, []byte(Schema), []byte("other-schema"), 1),
		bytes.Replace(raw, []byte(`"subject_source":"ip"`), []byte(`"subject_source":"invalid"`), 1))
	return corpus
}

func TestSelectedCaptureEquivalence(t *testing.T) {
	for _, raw := range selectedCorpus(t) {
		checkSelected(t, raw)
	}
	raw, _ := metadataFixture(t)
	for i := range raw {
		checkSelected(t, raw[:i])
	}
}

func TestSelectedCaptureSizeBoundaries(t *testing.T) {
	raw, _ := metadataFixture(t)
	for _, size := range []int{512 << 10, (512 << 10) + 1, (1 << 20) + 1} {
		padded := append(bytes.Repeat([]byte{' '}, size-len(raw)), raw...)
		checkSelected(t, padded)
		checkSelected(t, bytes.Replace(padded, []byte(Schema), []byte("other-schema"), 1))
	}
}

func FuzzSelectedCaptureEquivalence(f *testing.F) {
	for _, raw := range selectedCorpus(f) {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) { checkSelected(t, raw) })
}

func FuzzSelectedCaptureMutation(f *testing.F) {
	raw, _ := metadataFixture(f)
	f.Add(uint16(0), byte('{'), byte(0))
	f.Add(uint16(100), byte('x'), byte(1))
	f.Fuzz(func(t *testing.T, offset uint16, value, mode byte) {
		body := bytes.Clone(raw)
		index := int(offset) % len(body)
		switch mode % 3 {
		case 0:
			body[index] = value
		case 1:
			body = append(body[:index:index], append([]byte{value}, body[index:]...)...)
		case 2:
			body = append(body[:index], body[index+1:]...)
		}
		checkSelected(t, body)
	})
}

func BenchmarkSelectedCapture(b *testing.B) {
	raw, _ := metadataFixture(b)
	for _, tc := range []struct {
		name string
		run  func([]byte) (decodedCapture, string, error)
	}{{"prior", referenceSelected}, {"selected", decodeSelected}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := tc.run(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
