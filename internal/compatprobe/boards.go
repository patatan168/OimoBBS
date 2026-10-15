// 試験板ディレクトリを管理操作から更新し、公開ルートは読取りだけを行う。
package compatprobe

import (
	"errors"
	"oimobbs/internal/compat"
	"sort"
	"strings"
	"unicode/utf8"
)

// boardByKey は作成済みの試験板だけを返す。公開要求で新しい板は作らない。
func (s *Server) boardByKey(key string) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boards[key]
}
func (s *Server) boardForPath(path string) *Server {
	prefix := strings.TrimPrefix(path, "/")
	if strings.HasPrefix(path, "/test/read.cgi/") {
		prefix = strings.TrimPrefix(path, "/test/read.cgi/")
	}
	key, _, _ := strings.Cut(prefix, "/")
	return s.boardByKey(key)
}

type menuBoard struct {
	Name string `json:"board_name"`
	URL  string `json:"url"`
	Path string `json:"-"`
}

func (s *Server) menuBoards() []menuBoard {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.boards))
	for k := range s.boards {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([]menuBoard, 0, len(keys))
	for _, key := range keys {
		board := s.boards[key]
		rows = append(rows, menuBoard{Name: board.name, URL: strings.TrimSuffix(s.base.String(), "/") + "/" + key + "/", Path: "/" + key + "/"})
	}
	return rows
}

// addBoard は管理ハンドラの認証・CSRF検証後にだけ呼び出す。
func (s *Server) addBoard(key, name string) error {
	if !boardPattern.MatchString(key) || key == "test" || key == "web" {
		return errors.New("板キーは英小文字で始まる英数字・_の32文字以内です。testとwebは予約済みです。")
	}
	normalized, e := compat.Normalize(name, false, false)
	if e != nil || strings.TrimSpace(normalized) == "" || utf8.RuneCountInString(normalized) > 128 {
		return errors.New("板名は改行を含まない1〜128文字で入力してください。")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.boards[key] != nil {
		return errors.New("その板キーはすでに使われています。")
	}
	if len(s.boards) >= 32 {
		return errors.New("試験板は32件までです。")
	}
	board, e := New(s.base.String())
	if e != nil {
		return e
	}
	board.slug = key
	board.name = normalized
	board.boards = nil
	board.clock = s.clock
	s.boards[key] = board
	return nil
}
