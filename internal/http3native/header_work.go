// 応答headerの整理と符号化に使う作業領域を再利用し、要求ごとの小さい割り当てを抑える。
package http3native

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"
)

type headerWork struct {
	keys   [32]string
	fields [32]Field
	wire   [512]byte
	frame  [16]byte
}

var headerWorkPool = sync.Pool{New: func() any { return new(headerWork) }}

// release は要求間でheader文字列を保持せず、QUICへコピーした後に呼ぶ。
func (h *headerWork) release() {
	clear(h.keys[:])
	clear(h.fields[:])
	clear(h.wire[:])
	headerWorkPool.Put(h)
}

func (h *headerWork) prefix(size int) []byte {
	return appendInteger(appendInteger(h.frame[:0], 1), uint64(size))
}

// headerBlock はpeerの上限を守り、HTTP/3で許される応答headerだけを符号化する。
func (w *responseWriter) headerBlock(status int, header http.Header, work *headerWork) ([]byte, error) {
	keys := work.keys[:0]
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fields := append(work.fields[:0], Field{":status", strconv.Itoa(status)})
	total := uint64(32 + len(fields[0].Name) + len(fields[0].Value))
	w.connection.mu.Lock()
	limit := min(w.connection.peerFieldLimit, 16<<10)
	w.connection.mu.Unlock()
	for _, key := range keys {
		name := strings.ToLower(key)
		if !httpguts.ValidHeaderFieldName(name) {
			continue
		}
		switch name {
		case "connection", "proxy-connection", "keep-alive", "upgrade", "transfer-encoding", "trailer":
			continue
		}
		for _, value := range header[key] {
			if !httpguts.ValidHeaderFieldValue(value) {
				continue
			}
			total += uint64(32 + len(name) + len(value))
			if total > limit {
				return nil, errors.New("response field section budget")
			}
			fields = append(fields, Field{name, value})
		}
	}
	if total > limit {
		return nil, errors.New("response field section budget")
	}
	return w.qpack.encodeInto(w.stream.ID(), fields, work.wire[:0])
}
