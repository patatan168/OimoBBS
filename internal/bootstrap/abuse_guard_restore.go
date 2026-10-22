// 起動時の検出索引を小さいheapで集約し、全投稿の本文由来索引を同時に複製しない。
package bootstrap

import (
	"container/heap"
	"oimobbs/internal/domain"
)

type guardEntryHeap []guardEntry

func (h guardEntryHeap) Len() int { return len(h) }
func (h guardEntryHeap) Less(i, j int) bool {
	if h[i].at == h[j].at {
		return h[i].id.String() < h[j].id.String()
	}
	return h[i].at < h[j].at
}
func (h guardEntryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *guardEntryHeap) Push(v any)   { *h = append(*h, v.(guardEntry)) }
func (h *guardEntryHeap) Pop() any {
	v := (*h)[len(*h)-1]
	(*h)[len(*h)-1] = guardEntry{}
	*h = (*h)[:len(*h)-1]
	return v
}

type guardRestore struct {
	entries, signatures guardEntryHeap
	overflow            domain.Time
}

// add は最新4096件の件数履歴と、最新128件の本文署名だけを保持する。
func (v *guardRestore) add(e guardEntry, body string) {
	if len(v.signatures) < 128 || e.at >= v.signatures[0].at {
		copy := e
		copy.signature = guardBodySignature(body)
		heap.Push(&v.signatures, copy)
		if len(v.signatures) > 128 {
			heap.Pop(&v.signatures)
		}
	}
	heap.Push(&v.entries, e)
	if len(v.entries) > guardHistoryLimit {
		old := heap.Pop(&v.entries).(guardEntry)
		v.overflow = max(v.overflow, old.at+guardHistorySeconds*1e9)
	}
}

// finish は保有する署名を本文なし履歴へ結合する。呼出元で時刻順に並べる。
func (v *guardRestore) finish() []guardEntry {
	signatures := map[domain.ID]guardSignature{}
	for _, e := range v.signatures {
		signatures[e.id] = e.signature
	}
	for i := range v.entries {
		v.entries[i].signature = signatures[v.entries[i].id]
	}
	return []guardEntry(v.entries)
}
