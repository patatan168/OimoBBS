// 確定済みのHTTP本文を一段の送信片へ分け、最初のヘッダと本文の予約を共有する。
package delivery

import (
	"errors"
	"io"
	"net/http"
)

// WriteResponse は本文まで確定した応答を送る。通常のWriteHeaderの確定時点は変えない。
func (w *Response) WriteResponse(status int, body []byte) (int, error) {
	return w.WriteResponseChecked(status, body, nil)
}

// WriteResponseChecked はヘッダと最初の本文を合計16KiB以下で予約し、以後は一段だけ分割する。
// 公開検査は帯域待ち後のヘッダ/各本文書込み直前に行う。予約量は失敗しても返さない。
func (w *Response) WriteResponseChecked(status int, body []byte, check func() error) (int, error) {
	if w.terminal != nil {
		return 0, w.terminal
	}
	if w.started {
		return w.WriteChecked(body, check)
	}
	if len(body) == 0 {
		return 0, w.WriteHeaderChecked(status, check)
	}
	if status < 200 || status > 599 || status == http.StatusNoContent || status == http.StatusNotModified {
		return 0, errors.New("unsupported response body status")
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", http.DetectContentType(body))
	}
	header := w.headerBytes(status)
	if header >= Chunk {
		if err := w.WriteHeaderChecked(status, check); err != nil {
			return 0, err
		}
		return w.WriteChecked(body, check)
	}
	size := min(len(body), Chunk-header, w.scheduler.bodyChunk())
	n, err := w.writeFirst(status, body[:size], header, check)
	if err != nil {
		return n, err
	}
	next, err := w.WriteChecked(body[size:], check)
	return n + next, err
}

// writeFirst は一つの送信枠でヘッダ・本文を下流へ渡し、枠をsocket書込み後に解放する。
func (w *Response) writeFirst(status int, body []byte, header int, check func() error) (int, error) {
	permit, err := w.reserve(header + len(body))
	if err != nil {
		w.fail(err)
		return 0, err
	}
	defer permit.Release()
	if err = w.checkBeforeWrite(check); err != nil {
		return 0, err
	}
	w.ResponseWriter.WriteHeader(status)
	w.started = true
	if err = w.checkBeforeWrite(check); err != nil {
		w.terminal = err
		return 0, err
	}
	n, err := w.ResponseWriter.Write(body)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.terminal = err
	}
	return n, err
}

// checkBeforeWrite は公開権限と要求取消を、予約待ち後に再評価する。
func (w *Response) checkBeforeWrite(check func() error) error {
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	return w.ctx.Err()
}
