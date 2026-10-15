// 管理スレッド一覧のJSON契約。非公開タイトルを再公開せず、版付きの有界ページを返す。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"sort"
	"strconv"
	"strings"
	"time"
)

type adminThreadListItem struct {
	Key          domain.U64 `json:"key"`
	Revision     domain.U64 `json:"revision"`
	Title        string     `json:"title"`
	PublicStatus int        `json:"public_status"`
	Expires      string     `json:"expires_at"`
}

func (h *adminHandler) adminThreadsList(w http.ResponseWriter, r *http.Request, session adminauth.Session) {
	query, err := adminThreadQuery(r)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/boards/"), "/")
	var owner domain.ID
	if len(parts) != 2 || parts[1] != "threads" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &owner) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	h.repo.mu.Lock()
	err = h.repo.authorizeAdmin(session, "board_admin", owner)
	b := h.repo.posting[owner]
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if b == nil {
		h.fail(w, r, 404, "BOARD_NOT_FOUND")
		return
	}
	result, err := b.worker.Submit(r.Context(), func() (any, error) {
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		rows := []adminThreadListItem{}
		now := domain.Time(b.clock().UnixNano())
		for key, log := range b.threads {
			seq, expiry, _, ok := log.RetentionState()
			if !ok {
				continue
			}
			title := "非公開スレッド"
			if summary := log.Summary(now); summary != nil {
				title = summary.Title
			}
			if !adminThreadMatches(title, query) {
				continue
			}
			rows = append(rows, adminThreadListItem{domain.U64(key), seq, title, log.PublicStatus(now), time.Unix(0, int64(expiry)).UTC().Format(time.RFC3339Nano)})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Key > rows[j].Key })
		return rows, nil
	})
	if err != nil {
		h.failure(w, r, err)
		return
	}
	rows := result.([]adminThreadListItem)
	keys := make([]string, len(rows))
	for i, row := range rows {
		keys[i] = strconv.FormatUint(uint64(row.Key), 10)
	}
	revision, err := adminListRevision(rows)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	window, err := adminListSlice(r, session, revision, keys, time.Now())
	if err != nil {
		h.failure(w, r, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(revision))
	adminJSON(w, 200, listMetadata(rows[window.Start:window.End], window, revision))
}
