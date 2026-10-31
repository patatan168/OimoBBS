// 板別の設定画面に、認可済みの板名・現在地と共通の設定タブを渡す。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
)

type boardNavigationLink struct {
	Label, Title, URL                   string
	Current, Disabled, SiteOnly, Danger bool
}

type adminBoardNavigation struct {
	Name, Key, CurrentTitle string
	Closed                  bool
	Links                   []boardNavigationLink
}

// boardNavigation は板別HTMLの認可を再検査し、他板や全体設定へ移動しないリンクを構成する。
func (h *adminHandler) boardNavigation(r *http.Request, s adminauth.Session) *adminBoardNavigation {
	if !strings.HasPrefix(r.URL.Path, "/boards/") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/boards/"), "/")
	var id domain.ID
	if len(parts) < 2 || json.Unmarshal([]byte(strconv.Quote(parts[0])), &id) != nil {
		return nil
	}
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()
	if h.repo.authorizeAdmin(s, "board_admin", id) != nil {
		return nil
	}
	view, err := h.repo.boardMetadataLocked(id)
	if err != nil {
		return nil
	}
	closed := h.repo.posting[id].closedAt.Load() != 0
	base := "/boards/" + id.String() + "/"
	links := []boardNavigationLink{
		{Label: "投稿設定", Title: "投稿設定", URL: base + "settings"},
		{Label: "板名・URL", Title: "板名・キーを変更", URL: base + "metadata", SiteOnly: true},
		{Label: "閲覧権限", Title: "板の閲覧権限を設定", URL: base + "reading"},
		{Label: "レス上限・終了レス", Title: "レス数上限・終了レス", URL: base + "thread-settings"},
		{Label: "投稿規制", Title: "投稿規制", URL: base + "rules"},
		{Label: "ローカルルール", Title: "ローカルルール", URL: base + "local-rules"},
		{Label: "レス管理", Title: "レス削除・投稿者規制", URL: base + "threads"},
		{Label: "板を閉鎖", Title: "板を閉鎖", URL: base + "close", SiteOnly: true, Danger: true},
	}
	current := parts[1]
	if current == "moderation" || current == "actions" {
		current = "threads"
	}
	nav := &adminBoardNavigation{Name: view.Name, Key: view.Key, Closed: closed}
	for _, link := range links {
		section := strings.TrimPrefix(link.URL, base)
		link.Current = section == current
		link.Disabled = closed && section != "settings" && section != "threads" && section != "close"
		if closed && section == "close" {
			link.Label, link.Title = "閉鎖状態", "閉鎖状態を確認"
			link.Danger = false
		}
		if link.Current {
			nav.CurrentTitle = link.Title
		}
		nav.Links = append(nav.Links, link)
	}
	if parts[1] == "threads" && len(parts) > 3 {
		switch parts[3] {
		case "posts":
			nav.CurrentTitle = "レスの管理"
		case "moderation":
			nav.CurrentTitle = "レスの削除・公開停止"
		case "actions":
			nav.CurrentTitle = "スレッドの状態変更"
		}
	}
	return nav
}
