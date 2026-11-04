// HTTP/3のfield値を中継先と同じ意味に保ち、前後の空白による解釈差を拒否する。
package http3native

import (
	"strings"

	"golang.org/x/net/http/httpguts"
)

// validFieldValue は内部のHTABと空の値を許可し、前後のSP/HTABと制御文字を拒否する。
func validFieldValue(value string) bool {
	return httpguts.ValidHeaderFieldValue(value) && strings.Trim(value, " \t") == value
}
