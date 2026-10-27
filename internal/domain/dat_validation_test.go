// DAT行の検証経路を変更前の文字列復号・制御文字検査と照合する。
package domain

import (
	"bytes"
	"testing"

	"oimobbs/internal/textcodec"
)

func referenceValidDATLine(line []byte) bool {
	if len(line) == 0 || line[len(line)-1] != '\n' || bytes.ContainsAny(line[:len(line)-1], "\x00\r\n") || bytes.Count(line, []byte("<>")) != 4 {
		return false
	}
	_, err := textcodec.Decode(line)
	return err == nil
}

func TestValidDATLineMatchesReference(t *testing.T) {
	for _, line := range [][]byte{nil, []byte("\n"), []byte("name<><>date<>body<>title\n"), []byte("name<><>date<>body<>title"), []byte("name<><>date<>bad\nbody<>title\n")} {
		if validDATLine(line) != referenceValidDATLine(line) {
			t.Fatalf("line validation differs: %x", line)
		}
	}
	line := []byte("name<><>date<>xx<>\n")
	for first := range 256 {
		for second := range 256 {
			line[13], line[14] = byte(first), byte(second)
			if validDATLine(line) != referenceValidDATLine(line) {
				t.Fatalf("line validation differs: %x", line)
			}
		}
	}
}

func FuzzValidDATLineMatchesReference(f *testing.F) {
	for _, line := range [][]byte{nil, []byte("name<><>date<>body<>title\n"), []byte("name<><>date<>\x82\xa0<>title\n"), []byte("name<><>date<>\x81<>title\n")} {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		if len(line) > 1<<16 {
			t.Skip()
		}
		if validDATLine(line) != referenceValidDATLine(line) {
			t.Fatalf("line validation differs: %x", line)
		}
	})
}
