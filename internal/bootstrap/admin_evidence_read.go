// 提出用記録APIのスナップショットをmutex内で固定し、解放後の送信でも失効を検査する。
package bootstrap

import (
	"net/http"
	"strconv"
	"strings"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
)

type evidenceCaseReply struct {
	data   map[string]any
	etag   string
	boards []domain.ID
}

// evidenceCaseResponse は担当・再認証を検査して案件の独立した値を返し、HTTP送信は行わない。
func (repo *Repository) evidenceCaseResponse(s adminauth.Session, r *http.Request, path string) (evidenceCaseReply, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if e := repo.authorizeEvidence(s, "evidence.manage", domain.ID{}, true); e != nil {
		return evidenceCaseReply{}, e
	}
	rows, e := repo.evidenceCases.Cases()
	if e != nil {
		return evidenceCaseReply{}, e
	}
	selected := []disclosure.Case{}
	var target domain.ID
	if strings.HasPrefix(path, "/evidence/cases/") {
		if target.UnmarshalJSON([]byte(strconv.Quote(strings.TrimPrefix(path, "/evidence/cases/")))) != nil {
			return evidenceCaseReply{}, &adminFailure{status: 404, code: "NOT_FOUND"}
		}
	}
	var window adminListWindow
	var revision string
	if target == (domain.ID{}) {
		rows, window, revision, e = repo.evidenceCasePageLocked(rows, s, r)
		if e != nil {
			return evidenceCaseReply{}, e
		}
	}
	boards := []domain.ID{}
	seenBoards := map[domain.ID]bool{}
	tokens := map[string]string{"/api/v1/evidence/cases": s.CSRF("/api/v1/evidence/cases"), "/api/v1/evidence/other-cases": s.CSRF("/api/v1/evidence/other-cases")}
	for _, c := range rows {
		if target != (domain.ID{}) && target != c.ID {
			continue
		}
		if repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true) != nil {
			continue
		}
		selected = append(selected, c)
		if !seenBoards[c.Scope.Board] {
			seenBoards[c.Scope.Board] = true
			boards = append(boards, c.Scope.Board)
		}
		for _, action := range []string{"hold", "http-hold", "http-observation-hold", "extend", "release", "exports", "extract", "rejected-hold", "rejected-exports", "extract-rejected", "extract-http"} {
			route := "/api/v1/evidence/cases/" + c.ID.String() + "/" + action
			tokens[route] = s.CSRF(route)
		}
		for _, v := range c.Exports {
			for _, action := range []string{"download", "resume"} {
				route := "/api/v1/evidence/exports/" + v.ID.String() + "/" + action
				tokens[route] = s.CSRF(route)
			}
		}
	}
	etag := `"evidence:new"`
	if target != (domain.ID{}) {
		if len(selected) == 0 {
			return evidenceCaseReply{}, &adminFailure{status: 404, code: "EVIDENCE_NOT_FOUND"}
		}
		etag = selected[0].ETag()
	}
	response := map[string]any{"data": selected, "dates": evidenceCaseHTTPValues(selected), "csrf_tokens": tokens, "cleanup_failed": repo.evidenceCleanupFailed}
	if target == (domain.ID{}) {
		response["limit"], response["next_cursor"], response["revision"], response["total"] = window.Limit, window.Next, revision, window.Total
	}
	return evidenceCaseReply{data: response, etag: etag, boards: boards}, nil
}

// checkedEvidenceCaseResponse は帯域待機後・各送信片の直前にセッション・権限・担当・再認証を再検査する。
func (h *adminHandler) checkedEvidenceCaseResponse(w http.ResponseWriter, s adminauth.Session, boards []domain.ID) http.ResponseWriter {
	return &adminCheckedWriter{ResponseWriter: w, check: func() error {
		h.repo.mu.Lock()
		defer h.repo.mu.Unlock()
		if err := h.repo.authorizeEvidence(s, "evidence.manage", domain.ID{}, true); err != nil {
			return err
		}
		account, err := h.repo.currentAdminAccount(s)
		if err != nil {
			return err
		}
		for _, board := range boards {
			if err := authorizeAdministrator(account, "moderator", board); err != nil {
				return err
			}
		}
		return nil
	}}
}
