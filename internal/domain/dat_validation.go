// 保存DATの改行・区切り・文字コードを、一時文字列を作らず検査する。
package domain

import (
	"bytes"

	"oimobbs/internal/textcodec"
)

// validDATLine は単一の終端改行、4区切り、制御文字不在とsjis-compat-v1を検査する。
func validDATLine(line []byte) bool {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return false
	}
	content := line[:len(line)-1]
	return bytes.IndexByte(content, 0) < 0 && bytes.IndexByte(content, '\r') < 0 && bytes.IndexByte(content, '\n') < 0 &&
		bytes.Count(content, []byte("<>")) == 4 && textcodec.Valid(content)
}
