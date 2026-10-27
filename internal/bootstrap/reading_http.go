// HTTPの閲覧許可をヘッダ・帯域予約後・各送信片で再確認し、共有キャッシュを抑止する。
package bootstrap

import (
	"net/http"
	"net/netip"
	"oimobbs/internal/domain"
)

// readingGate は実接続元、または認証済みedgeが確定した接続元で判定する。未検証の転送ヘッダは使用しない。
func (repo *Repository) readingGate(w http.ResponseWriter, r *http.Request, scope string) (http.ResponseWriter, bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	ip := peer.Addr()
	if err != nil {
		ip = netip.Addr{}
	}
	repo.prepareReading(r.Context(), scope, ip)
	if repo.checkReading(scope, ip, r.UserAgent()) != nil {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		threadError(w, r, 403, "この接続元からの閲覧は許可されていません。")
		return w, true
	}
	snapshot := repo.liveReading.Load()
	classifier := repo.liveNetworks.Load()
	private := false
	if snapshot != nil {
		for key, p := range snapshot.Policies {
			if scope == "admin" && key == "admin" || scope != "admin" && key != "admin" {
				private = private || p.Policy.Enabled
			}
		}
	}
	check := func() error {
		if err := r.Context().Err(); err != nil {
			return err
		}
		// 一覧・検索を組み立てた後の設定変更でも古い許可済み内容を配信しない。
		current := repo.liveReading.Load()
		changed := (current == nil) != (snapshot == nil)
		if current != nil && snapshot != nil {
			changed = current.PublicRevision != snapshot.PublicRevision
		}
		if scope != "admin" && (changed || private && repo.liveNetworks.Load() != classifier) {
			return errReadingDenied
		}
		return repo.checkReading(scope, ip, r.UserAgent())
	}
	return &readingResponse{ResponseWriter: w, check: check, private: private}, false
}

// readableBoards は取得を許可しない板の名前や件数を、メニュー・検索へ渡さない。
func (repo *Repository) readableBoards(r *http.Request, boards []publicBoard) []publicBoard {
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	out := make([]publicBoard, 0, len(boards))
	if snapshot := repo.liveReading.Load(); snapshot != nil {
		for _, board := range boards {
			p := snapshot.Policies[board.ID.String()]
			if p != nil && p.Policy.Enabled && (p.Policy.Network.denyUnresolvedHost() || len(p.Policy.Network.DeniedKinds) > 0) {
				repo.prepareReading(r.Context(), board.ID.String(), peer.Addr())
				break
			}
		}
	}
	for _, board := range boards {
		if repo.checkReading(board.ID.String(), peer.Addr(), r.UserAgent()) == nil {
			out = append(out, board)
		}
	}
	return out
}

// readingBoardGate は閲覧の許可を投稿にも必要とし、公開側の全操作に同じ条件を適用する。
func (repo *Repository) readingBoardGate(w http.ResponseWriter, r *http.Request, owner domain.ID) (http.ResponseWriter, bool) {
	return repo.readingGate(w, r, owner.String())
}

type readingResponse struct {
	http.ResponseWriter
	check            func() error
	private, written bool
}

func (w *readingResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// combined は削除リース等の下流から渡された検査も維持する。
func (w *readingResponse) combined(extra func() error) func() error {
	return func() error {
		if err := w.check(); err != nil {
			return err
		}
		if extra != nil {
			return extra()
		}
		return nil
	}
}
func (w *readingResponse) prepare() {
	if w.private {
		if w.Header().Get("Cache-Control") != "no-store" {
			w.Header().Set("Cache-Control", "private, no-store")
		}
	}
}

// reject はまだ送っていない応答の本文・圧縮・条件付き応答ヘッダを破棄する。
func (w *readingResponse) reject() {
	if w.written {
		return
	}
	for _, name := range []string{"Content-Length", "Content-Encoding", "Content-Range", "ETag", "Last-Modified"} {
		w.Header().Del(name)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.ResponseWriter.WriteHeader(403)
	w.written = true
}
func (w *readingResponse) WriteHeader(status int) { _ = w.WriteHeaderChecked(status, nil) }

// WriteHeaderChecked は帯域待機の後にも閲覧条件を確認する。
func (w *readingResponse) WriteHeaderChecked(status int, extra func() error) error {
	if w.written {
		return nil
	}
	check := w.combined(extra)
	if err := check(); err != nil {
		if w.check() != nil {
			w.reject()
		}
		return err
	}
	w.prepare()
	if lower, ok := w.ResponseWriter.(interface{ WriteHeaderChecked(int, func() error) error }); ok {
		if err := lower.WriteHeaderChecked(status, check); err != nil {
			if w.check() != nil {
				w.reject()
			}
			return err
		}
	} else {
		w.ResponseWriter.WriteHeader(status)
	}
	w.written = true
	return nil
}
func (w *readingResponse) Write(body []byte) (int, error) { return w.WriteChecked(body, nil) }

// WriteChecked は16KiBごとの検査を下流の送信予約まで伝える。
func (w *readingResponse) WriteChecked(body []byte, extra func() error) (int, error) {
	check := w.combined(extra)
	if err := check(); err != nil {
		if w.check() != nil {
			w.reject()
		}
		return 0, err
	}
	if !w.written {
		if err := w.WriteHeaderChecked(200, extra); err != nil {
			return 0, err
		}
	}
	if lower, ok := w.ResponseWriter.(interface {
		WriteChecked([]byte, func() error) (int, error)
	}); ok {
		return lower.WriteChecked(body, check)
	}
	return writeCheckedFallback(w.ResponseWriter, body, check)
}
func (w *readingResponse) WriteResponse(status int, body []byte) (int, error) {
	return w.WriteResponseChecked(status, body, nil)
}

// WriteResponseChecked はDATの一括送信でも条件付き応答と公開リースの検査を保つ。
func (w *readingResponse) WriteResponseChecked(status int, body []byte, extra func() error) (int, error) {
	check := w.combined(extra)
	if err := check(); err != nil {
		if w.check() != nil {
			w.reject()
		}
		return 0, err
	}
	w.prepare()
	if lower, ok := w.ResponseWriter.(interface {
		WriteResponseChecked(int, []byte, func() error) (int, error)
	}); ok && !w.written {
		n, err := lower.WriteResponseChecked(status, body, check)
		w.written = err == nil || n > 0
		if err != nil && w.check() != nil {
			w.reject()
		}
		return n, err
	}
	if err := w.WriteHeaderChecked(status, extra); err != nil {
		return 0, err
	}
	return w.WriteChecked(body, extra)
}

// FlushError はUnwrap経由の直接flushを防ぐ。
func (w *readingResponse) FlushError() error {
	if err := w.check(); err != nil {
		w.reject()
		return err
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// readingListWriter は一覧に含めた板の許可も送信時に再検査し、板の手動分類変更による取得を防ぐ。
func (repo *Repository) readingListWriter(w http.ResponseWriter, r *http.Request, boards []publicBoard) http.ResponseWriter {
	snapshot := repo.liveReading.Load()
	scopes := []string{}
	if snapshot != nil {
		for _, board := range boards {
			if p := snapshot.Policies[board.ID.String()]; p != nil && p.Policy.Enabled {
				scopes = append(scopes, board.ID.String())
			}
		}
	}
	if len(scopes) == 0 {
		return w
	}
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	check := func() error {
		for _, scope := range scopes {
			if err := repo.checkReading(scope, peer.Addr(), r.UserAgent()); err != nil {
				return err
			}
		}
		return nil
	}
	return &readingResponse{ResponseWriter: w, check: check, private: true}
}
