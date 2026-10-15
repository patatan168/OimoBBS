// 証拠案件一覧を現在の担当板へ絞り、既存の10分署名カーソルでページ化する。
package bootstrap

import (
	"net/http"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
)

// evidenceCasePageLocked はrepo.mu保持下で現在認可後に呼ぶ。担当外案件を版/キーへ含めない。
func (r *Repository) evidenceCasePageLocked(rows []disclosure.Case, session adminauth.Session, request *http.Request) ([]disclosure.Case, adminListWindow, string, error) {
	selected := []disclosure.Case{}
	keys := []string{}
	for _, c := range rows {
		if r.authorizeEvidence(session, "evidence.manage", c.Scope.Board, true) == nil {
			selected = append(selected, c)
			keys = append(keys, c.ID.String())
		}
	}
	revision, err := adminListRevision(selected)
	if err != nil {
		return nil, adminListWindow{}, "", err
	}
	window, err := adminListSlice(request, session, revision, keys, time.Now())
	if err != nil {
		return nil, window, "", err
	}
	return selected[window.Start:window.End], window, revision, nil
}

// evidenceHTMLListRequest は変更後の結果画面も同じHTML一覧経路へ束縛する。
func evidenceHTMLListRequest(request *http.Request) *http.Request {
	cloned := request.Clone(request.Context())
	u := *request.URL
	u.Path = "/evidence"
	cloned.URL = &u
	return cloned
}
