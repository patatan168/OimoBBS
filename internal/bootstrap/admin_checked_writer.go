// 管理応答の送信を小さく区切り、送信中の権限・期限失効で中断する。
package bootstrap

import (
	"io"
	"net/http"
)

// adminCheckedWriter は最大32KiBごとの送信直前に失効を検査する。失効後はHTTP応答を中断する。
type adminCheckedWriter struct {
	http.ResponseWriter
	check func() error
}

func (w *adminCheckedWriter) WriteHeader(status int) {
	if w.check() != nil {
		panic(http.ErrAbortHandler)
	}
	if checked, ok := w.ResponseWriter.(interface{ WriteHeaderChecked(int, func() error) error }); ok {
		if checked.WriteHeaderChecked(status, w.check) != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write は元writerへ小さな区切りで渡し、返されたbytesとerrorを維持する。
func (w *adminCheckedWriter) Write(raw []byte) (int, error) {
	written := 0
	for len(raw) > 0 {
		if w.check() != nil {
			panic(http.ErrAbortHandler)
		}
		size := min(len(raw), 32<<10)
		var n int
		var e error
		if checked, ok := w.ResponseWriter.(interface {
			WriteChecked([]byte, func() error) (int, error)
		}); ok {
			n, e = checked.WriteChecked(raw[:size], w.check)
			if e != nil {
				panic(http.ErrAbortHandler)
			}
		} else {
			n, e = w.ResponseWriter.Write(raw[:size])
		}
		written += n
		if e != nil {
			return written, e
		}
		if n != size {
			return written, io.ErrShortWrite
		}
		raw = raw[size:]
	}
	return written, nil
}
