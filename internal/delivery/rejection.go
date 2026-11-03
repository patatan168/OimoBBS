// HTTP/1の早期拒否で、未受信本文の破棄待ちによる接続枠の占有を防ぐ。
package delivery

import (
	"errors"
	"net/http"
	"time"
)

// RejectUnreadBody は本文を読む前の拒否で呼び、HTTP/1の接続再利用と受信待ちを止める。
// HTTP/2の別streamや本文のない要求には触れない。実接続の期限設定失敗は切断へ戻し、
// ResponseRecorder等の期限非対応writerではConnection: closeだけを設定する。
func RejectUnreadBody(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 1 || r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
		return
	}
	w.Header().Set("Connection", "close")
	if err := http.NewResponseController(w).SetReadDeadline(time.Now()); err != nil && !errors.Is(err, http.ErrNotSupported) {
		panic(http.ErrAbortHandler)
	}
}
