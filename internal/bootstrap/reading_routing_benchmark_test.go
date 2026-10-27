// サイト全体の書込みを伴わない板解決が、並行閲覧で直列化しないことを測る。
package bootstrap

import (
	"testing"

	"oimobbs/internal/domain"
)

func BenchmarkPublicBoardRoutingParallel(b *testing.B) {
	owner := domain.ID{1}
	repo := &Repository{posting: map[domain.ID]*postingBoard{owner: {owner: owner, slug: "probe", publicName: "板"}}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			board, err := repo.webBoard("probe")
			if err != nil || board == nil {
				b.Fatal(board, err)
			}
			if _, err = repo.postingOwner(owner); err != nil {
				b.Fatal(err)
			}
			if slugs := repo.protectedBoardSlugs(); len(slugs) != 0 {
				b.Fatal(slugs)
			}
		}
	})
}
