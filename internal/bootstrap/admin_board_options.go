// 管理画面の板選択を現在の担当範囲から取得し、複数チェックを従来の保存入力へ正規化する。
package bootstrap

import (
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"slices"
	"sort"
	"strings"
)

type boardOption struct {
	ID        domain.ID
	Key, Name string
	Checked   bool
}

// boardOptions は担当外の板名やIDを返さず、編集中の選択状態を付ける。
func (r *Repository) boardOptions(s adminauth.Session, selected []domain.ID) ([]boardOption, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, e := r.currentAdminSession(s)
	if e != nil {
		return nil, e
	}
	scope := newCapScope(a)
	rows := []boardOption{}
	for id, b := range r.posting {
		if !scope.allows([]domain.ID{id}) {
			continue
		}
		rows = append(rows, boardOption{id, b.slug, b.publicName, slices.Contains(selected, id)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows, nil
}

// normalizeBoardSelection はチェック省略を空集合へ変換し、重複や不正な値を拒否する。
func normalizeBoardSelection(v url.Values) error {
	if !v.Has("board_selection") {
		return nil
	}
	if len(v["board_selection"]) != 1 || v.Get("board_selection") != "1" {
		return ErrPostingRequest
	}
	if len(v["board_ids"]) == 1 && v.Get("board_ids") == "" {
		v.Del("board_ids")
	}
	seen := map[string]bool{}
	for _, id := range v["board_ids"] {
		var parsed domain.ID
		if parsed.UnmarshalJSON([]byte(`"`+id+`"`)) != nil || parsed == (domain.ID{}) || seen[id] {
			return ErrPostingRequest
		}
		seen[id] = true
	}
	v.Set("board_ids", strings.Join(v["board_ids"], " "))
	v.Del("board_selection")
	return nil
}
