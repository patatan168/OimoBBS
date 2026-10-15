// サイトと専ブラの板一覧を、同じカテゴリー順・板割当で構成する。
package bootstrap

import (
	"sort"

	"oimobbs/internal/domain"
)

type publicBoardGroup struct {
	Name   string
	Boards []publicBoard
	Order  uint32
}

// groupPublicBoards は未分類の板を最後に置き、空のカテゴリーを公開一覧から除く。
func groupPublicBoards(title string, boards []publicBoard) []publicBoardGroup {
	groups := []publicBoardGroup{}
	indexes := map[domain.ID]int{}
	for _, b := range boards {
		index, ok := indexes[b.CategoryID]
		if !ok {
			name := b.CategoryName
			if name == "" {
				name = title
			}
			index = len(groups)
			indexes[b.CategoryID] = index
			groups = append(groups, publicBoardGroup{Name: name, Order: b.CategoryOrder, Boards: []publicBoard{}})
		}
		groups[index].Boards = append(groups[index].Boards, b)
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Order < groups[j].Order })
	return groups
}
