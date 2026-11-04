// 全本文が既に用意された応答だけを集約し、16KiBごとの予算検査とQUICへのコピーを両立する。
package http3native

import "strconv"

// PrepareBody は全本文が既にあることをdeliveryから受け取る。ここでは確保・I/Oをしない。
// 汎用の逐次生成・ストリーミング応答は対象にせず、最大64KiBの確定済み応答だけを候補にする。
func (w *responseWriter) PrepareBody(size int) {
	if !w.sent && size > 4096 && size <= 64<<10 {
		w.bodyHint = size
	}
}

// prepareBodyFrame は通常の各Writeで認可・予約されたbyteだけを準備領域へコピーする。
// HEADERSとDATA prefixを含め最大65KiBとし、handler終了前にはFINを送らない。
func (w *responseWriter) prepareBodyFrame(prefix, block, tail []byte) (bool, error) {
	if w.bodyHint == 0 || w.snapshot.Get("Content-Length") != strconv.Itoa(w.bodyHint) {
		return false, nil
	}
	dataHeader := dataPrefix(w.bodyHint)
	overhead := len(prefix) + len(block) + len(dataHeader)
	if overhead > 1024 {
		return false, nil
	}
	prepared, err := w.stream.NewWriteBuffer(w.bodyHint + overhead)
	if err != nil {
		return true, err
	}
	if err = prepared.Append(prefix, block, dataHeader, w.buffer, tail); err != nil {
		prepared.Abort()
		return true, err
	}
	w.bodyBuffer, w.bodyFramed, w.sent = prepared, true, true
	w.buffer = nil
	if w.written == int64(w.bodyHint) {
		return true, w.commitBodyBuffer()
	}
	return true, nil
}

// commitBodyBuffer はHTTP要求の取消も再確認してから、準備領域をflow制御付き送信へ移す。
func (w *responseWriter) commitBodyBuffer() error {
	prepared := w.bodyBuffer
	w.bodyBuffer = nil
	if err := w.request.Context().Err(); err != nil {
		prepared.Abort()
		return err
	}
	return prepared.CommitContext(w.request.Context())
}
