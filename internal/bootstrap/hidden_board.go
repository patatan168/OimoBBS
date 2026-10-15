// 専ブラ閲覧板の検索とWeb閲覧を制限し、直接登録した専ブラのデータ取得を維持する。
package bootstrap

import (
	"net/http"
	"strings"
)

// unlisted は未設定の旧板を通常公開として解決する。
func (p boardPresentation) unlisted() bool { return p.Hidden != nil && *p.Hidden }

// searchableBoards はWeb本文を閲覧できる板だけを検索対象として抽出する。
func searchableBoards(boards []publicBoard) []publicBoard {
	rows := make([]publicBoard, 0, len(boards))
	for _, board := range boards {
		if !board.Hidden {
			rows = append(rows, board)
		}
	}
	return rows
}

// hiddenBoardWebGate はWebの本文閲覧・投稿フォームを本文参照前に403へ閉じる。
// 専ブラが直接登録する板トップ・subject・DAT・設定・CGI投稿は維持する。
func (repo *Repository) hiddenBoardWebGate(w http.ResponseWriter, r *http.Request) bool {
	slug := ""
	if strings.HasPrefix(r.URL.Path, "/test/read.cgi/") {
		slug = strings.Split(strings.TrimPrefix(r.URL.Path, "/test/read.cgi/"), "/")[0]
	} else if r.URL.Path == "/web/post" {
		slug = r.URL.Query().Get("bbs")
	}
	if slug == "" {
		return false
	}
	repo.mu.Lock()
	hidden := false
	for _, board := range repo.posting {
		if board.slug == slug {
			hidden = board.hidden.Load()
			break
		}
	}
	repo.mu.Unlock()
	if !hidden {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	threadError(w, r, http.StatusForbidden, "この板は専用ブラウザから閲覧・投稿してください。")
	return true
}
