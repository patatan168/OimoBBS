// DAT/HTMLの送信片ごとに削除世代・期限を検査し、失効したsocketの書込みを中断する。
package bootstrap

import (
	"context"
	"io"
	"net/http"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"time"
)

type publicResponse struct {
	http.ResponseWriter
	lease       *app.PublicLease
	leases      []*app.PublicLease
	leaseClocks []func() time.Time
	clock       func() time.Time
	ctx         context.Context
	written     bool
}

// publicWriter はコピー済みsnapshotにも有効な送信リースを取得する。
func publicWriter(w http.ResponseWriter, r *http.Request, s *app.PostingSnapshot, clock func() time.Time) (*publicResponse, error) {
	controller := http.NewResponseController(w)
	lease, e := s.AcquirePublic(domain.Time(clock().UnixNano()), func() { _ = controller.SetWriteDeadline(time.Now()) })
	if e != nil {
		return nil, e
	}
	return &publicResponse{ResponseWriter: w, lease: lease, clock: clock, ctx: r.Context()}, nil
}
func (w *publicResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *publicResponse) check() error {
	if e := w.ctx.Err(); e != nil {
		return e
	}
	now := domain.Time(w.clock().UnixNano())
	if w.lease != nil {
		if e := w.lease.Check(now); e != nil {
			return e
		}
	}
	for i, lease := range w.leases {
		leaseNow := now
		if i < len(w.leaseClocks) {
			leaseNow = domain.Time(w.leaseClocks[i]().UnixNano())
		}
		if e := lease.Check(leaseNow); e != nil {
			return e
		}
	}
	return nil
}
func (w *publicResponse) WriteHeader(status int) {
	if w.written {
		return
	}
	if w.check() != nil {
		w.Header().Del("Content-Length")
		w.Header().Del("Content-Encoding")
		w.ResponseWriter.WriteHeader(410)
		w.written = true
		return
	}
	if checked, ok := w.ResponseWriter.(interface{ WriteHeaderChecked(int, func() error) error }); ok {
		if checked.WriteHeaderChecked(status, w.check) != nil {
			w.Header().Del("Content-Length")
			w.Header().Del("Content-Encoding")
			w.ResponseWriter.WriteHeader(410)
		}
	} else {
		w.ResponseWriter.WriteHeader(status)
	}
	w.written = true
}
func (w *publicResponse) Write(body []byte) (int, error) {
	if e := w.check(); e != nil {
		return 0, e
	}
	if !w.written {
		w.WriteHeader(200)
	}
	total := 0
	for len(body) > 0 {
		if e := w.check(); e != nil {
			return total, e
		}
		size := min(len(body), 16<<10)
		var n int
		var e error
		if checked, ok := w.ResponseWriter.(interface {
			WriteChecked([]byte, func() error) (int, error)
		}); ok {
			n, e = checked.WriteChecked(body[:size], w.check)
		} else {
			n, e = w.ResponseWriter.Write(body[:size])
		}
		total += n
		if e != nil {
			return total, e
		}
		if n != size {
			return total, io.ErrShortWrite
		}
		body = body[size:]
	}
	return total, nil
}

// WriteResponse は確定本文を一段の帯域分割へ渡し、ヘッダ/各送信片の公開検査を維持する。
// 最初の公開検査で失効した場合は既存の410応答へ戻し、本文を送らない。
func (w *publicResponse) WriteResponse(status int, body []byte) (int, error) {
	if err := w.check(); err != nil {
		w.WriteHeader(status)
		return 0, err
	}
	if !w.written {
		if writer, ok := w.ResponseWriter.(interface {
			WriteResponseChecked(int, []byte, func() error) (int, error)
		}); ok {
			n, err := writer.WriteResponseChecked(status, body, w.check)
			if err != nil {
				w.WriteHeader(status)
			} else {
				w.written = true
			}
			return n, err
		}
	}
	w.WriteHeader(status)
	return w.Write(body)
}

// FlushError はResponseControllerのflushにも世代・期限・取消の検査を適用する。
// Unwrap経由で元writerへ直接flushされることを防ぎ、下位の送信エラーをそのまま返す。
func (w *publicResponse) FlushError() error {
	if e := w.check(); e != nil {
		return e
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Close は一覧に含む全対象の送信リースを必ず解放する。
func (w *publicResponse) Close() {
	if w.lease != nil {
		w.lease.Close()
	}
	for _, l := range w.leases {
		l.Close()
	}
}

// publicListingWriter は送信するタイトル集合へ、本文を複製せずリースを取得する。
func (repo *Repository) publicListingWriter(w http.ResponseWriter, r *http.Request, owner domain.ID, rows []publicThread) (*publicResponse, error) {
	b, e := repo.postingOwner(owner)
	if e != nil {
		return nil, e
	}
	result := &publicResponse{ResponseWriter: w, clock: b.clock, ctx: r.Context()}
	controller := http.NewResponseController(w)
	for _, row := range rows {
		l, e := row.publication.AcquirePublic(domain.Time(b.clock().UnixNano()), func() { _ = controller.SetWriteDeadline(time.Now()) })
		if e != nil {
			result.Close()
			return nil, e
		}
		result.leases = append(result.leases, l)
	}
	return result, nil
}
