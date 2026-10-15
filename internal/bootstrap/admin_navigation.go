// 管理画面のメニューを現在のロールと追加権限から決める。再認証は各操作の実行時に検査する。
package bootstrap

import "oimobbs/internal/adminaccess"

// adminNavigation は非公開情報の許可を含め、利用できる管理ページだけを表示する。
func adminNavigation(a administrator) map[string]bool {
	menu := map[string]bool{"/manual": true, "/auto-reports": true}
	if adminRoleRank[a.Role] >= adminRoleRank["board_admin"] {
		for _, path := range []string{"/boards", "/audit", "/caps"} {
			menu[path] = true
		}
	}
	if a.Role == "site_admin" {
		for _, path := range []string{"/", "/waf", "/abuse-guard", "/operations", "/board-categories", "/anonymous", "/reading", "/admin-access", "/networks", "/maintenance", "/administrators"} {
			menu[path] = true
		}
	}
	menu["/reports"] = adminaccess.Granted(a.Role, a.Permissions, "private_reports.read")
	menu["/evidence"] = adminaccess.Granted(a.Role, a.Permissions, "evidence.manage")
	return menu
}
