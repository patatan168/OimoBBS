// 板IDを維持した表示名・公開キーと旧キーの別名を、不変な値として共有する。
package bootstrap

import (
	"slices"

	"oimobbs/internal/store"
)

const boardMetadataReader = 104
const boardAliasLimit = 64

type boardMetadata struct {
	Key, Name string
	Aliases   []string
}

// metadata は実行中の変更を一度のatomic読取りで取得する。初期値は起動後に変更しない。
func (b *postingBoard) metadata() boardMetadata {
	if v := b.liveMetadata.Load(); v != nil {
		return *v
	}
	return boardMetadata{Key: b.slug, Name: b.publicName}
}
func (b *postingBoard) boardKey() string  { return b.metadata().Key }
func (b *postingBoard) boardName() string { return b.metadata().Name }
func (b *postingBoard) matchesKey(key string) bool {
	v := b.metadata()
	return v.Key == key || slices.Contains(v.Aliases, key)
}

// publishMetadata は保存成功後だけ呼ぶ。公開した別名sliceは以後変更しない。
func (b *postingBoard) publishMetadata(d boardDirectory) {
	name := d.Name
	if name == "" {
		name = b.publicName
	}
	b.liveMetadata.Store(&boardMetadata{Key: d.Key, Name: name, Aliases: slices.Clone(d.Aliases)})
}

func (d boardDirectory) matchesKey(key string) bool {
	return d.Key == key || slices.Contains(d.Aliases, key)
}

// validateMetadata は公開キーと別名の一意性・正規順・容量を検査する。
func (d boardDirectory) validateMetadata() error {
	if !validBoardKey(d.Key) || d.Name != "" && !validName(d.Name) || len(d.Aliases) > boardAliasLimit {
		return store.ErrCorrupt
	}
	for i, alias := range d.Aliases {
		if !validBoardKey(alias) || alias == d.Key || i > 0 && d.Aliases[i-1] >= alias {
			return store.ErrCorrupt
		}
	}
	if d.Status != "active" && (d.Name != "" || len(d.Aliases) != 0) {
		return store.ErrCorrupt
	}
	return nil
}

// validateMetadataTransition は過去の公開キーを予約し続け、他の板への再割当てを防ぐ。
func validateMetadataTransition(prior, next boardDirectory) error {
	if !next.matchesKey(prior.Key) {
		return store.ErrCorrupt
	}
	for _, alias := range prior.Aliases {
		if !next.matchesKey(alias) {
			return store.ErrCorrupt
		}
	}
	return nil
}

// presentAdminBoard は過去の設定receiptを改変せず、現在の板名・キーを応答へ反映する。
func (b *postingBoard) presentAdminBoard(v AdminBoard) AdminBoard {
	m := b.metadata()
	v.Key, v.Name = m.Key, m.Name
	return v
}
