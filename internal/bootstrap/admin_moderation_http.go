// 削除APIの認証・CSRF・CAS・要求IDを、先行intentと同じ保存経路へ接続する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

func (h *adminHandler) moderation(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	prefix := "/boards/"
	if api {
		prefix = "/api/v1/boards/"
	}
	cleanup := strings.HasSuffix(r.URL.Path, "/moderation/cleanup")
	path := r.URL.Path
	if cleanup {
		path = strings.TrimSuffix(path, "/cleanup")
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	var owner domain.ID
	if len(parts) != 4 || parts[1] != "threads" || parts[3] != "moderation" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &owner) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	key, e := strconv.ParseUint(parts[2], 10, 64)
	if e != nil || key == 0 || fmt.Sprint(key) != parts[2] {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	if cleanup {
		if api {
			h.fail(w, r, 404, "NOT_FOUND")
			return
		}
		h.redactionCleanupHTML(w, r, s, owner, key)
		return
	}
	if !api {
		h.moderationHTML(w, r, s, owner, key)
		return
	}
	route := r.URL.Path
	if r.Method == "GET" {
		h.repo.mu.Lock()
		e = h.repo.authorizeAdmin(s, "moderator", owner)
		b := h.repo.posting[owner]
		canReadHistory := h.repo.authorizeAdmin(s, "board_admin", owner) == nil
		h.repo.mu.Unlock()
		if e != nil {
			h.failure(w, r, e)
			return
		}
		if b == nil {
			h.fail(w, r, 404, "BOARD_NOT_FOUND")
			return
		}
		value, e := b.worker.Submit(r.Context(), func() (any, error) {
			p := b.threads[key]
			if p == nil {
				return nil, &adminFailure{status: 404, code: "THREAD_NOT_FOUND"}
			}
			seq, _, _, ok := p.RetentionState()
			if !ok {
				return nil, ErrPostingUnavailable
			}
			records, tasks := []DeletionRecord{}, []DeletionCopyTask{}
			var err error
			if canReadHistory {
				records, tasks, err = deletionHistory(b.deletions[key])
			}
			if err != nil {
				return nil, err
			}
			records, tasks, window, revision, err := moderationHistoryWindow(r, s, records, tasks)
			if err != nil {
				return nil, err
			}
			return moderationHTTPRead{seq, deletionHTTPValues(records), deletionTaskHTTPValues(tasks), window, revision}, nil
		})
		if e != nil {
			h.failure(w, r, e)
			return
		}
		data := value.(moderationHTTPRead)
		w.Header().Set("ETag", fmt.Sprintf(`"%s:%d:%d"`, owner, key, data.Revision))
		w.Header().Set("X-CSRF-Token", s.CSRF(route))
		adminJSON(w, 200, listMetadata(data, data.Window, data.ListRevision))
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	csrf, _, e := singleRequestHeader(r.Header, "X-CSRF-Token")
	if e != nil || !s.CheckCSRF(route, csrf) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	etag, exists, e := singleRequestHeader(r.Header, "If-Match")
	if e != nil {
		h.fail(w, r, 400, "INVALID_REVISION")
		return
	}
	if !exists {
		h.fail(w, r, 428, "REVISION_REQUIRED")
		return
	}
	requestID, _, e := singleRequestHeader(r.Header, "Idempotency-Key")
	if e != nil {
		h.fail(w, r, 400, "INVALID_REQUEST_KEY")
		return
	}
	content, _, e := singleRequestHeader(r.Header, "Content-Type")
	media, params, e2 := mime.ParseMediaType(content)
	if e != nil || e2 != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		h.fail(w, r, 415, "JSON_REQUIRED")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil {
		h.fail(w, r, 413, "BODY_TOO_LARGE")
		return
	}
	var edit AdminModeration
	if strictjson.Decode(raw, &edit) != nil {
		h.fail(w, r, 400, "INVALID_JSON")
		return
	}
	v, e := h.repo.ModerateThread(r.Context(), s, owner, key, edit, etag, requestID)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%s:%d:%d"`, owner, key, *v.TargetSeq))
	adminJSON(w, 200, map[string]any{"data": deletionHTTPValue(v), "public_applied": v.Phase == "applied" || v.Phase == "cleaning", "cleanup_complete": false})
}
