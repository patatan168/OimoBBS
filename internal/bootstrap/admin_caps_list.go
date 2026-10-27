// 大きい担当板配列をページ外へ複製せず、認証済みの不変registryから資格一覧を選ぶ。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"sort"
	"time"
)

func (r *Repository) adminCapsSelection(session adminauth.Session, request *http.Request, target domain.ID) ([]AdminCap, domain.U64, adminListWindow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account, err := r.currentCapAdministrator(session)
	if err != nil {
		return nil, 0, adminListWindow{}, err
	}
	scope := newCapScope(account)
	registry := r.liveCaps.Load()
	if registry == nil {
		return nil, 0, adminListWindow{}, ErrPostingUnavailable
	}
	revision := scopedCapRevision(scope, registry)
	if target != (domain.ID{}) {
		value, ok := registry.Records[target]
		if !ok || !scope.allows(value.Boards) {
			return nil, 0, adminListWindow{}, &adminFailure{status: 404, code: "CAP_NOT_FOUND"}
		}
		return []AdminCap{capView(value)}, revision, adminListWindow{}, nil
	}
	ids := []domain.ID{}
	for id, value := range registry.Records {
		if scope.allows(value.Boards) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = id.String()
	}
	window, err := adminListSlice(request, session, capListETag(revision), keys, time.Now())
	if err != nil {
		return nil, 0, adminListWindow{}, err
	}
	rows := make([]AdminCap, 0, window.End-window.Start)
	for _, id := range ids[window.Start:window.End] {
		rows = append(rows, capView(registry.Records[id]))
	}
	return rows, revision, window, nil
}
