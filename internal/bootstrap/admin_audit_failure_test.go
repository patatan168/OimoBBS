// 監査の準備中・ページ送り枠の不足・索引容量を別の回復手順として表示する。
package bootstrap

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminAuditFailureRecoveryAdvice(t *testing.T) {
	for _, tc := range []struct {
		code, want, absent string
	}{
		{"AUDIT_CATCH_UP_PENDING", "管理操作の記録を準備しています", "取得できません"},
		{"AUDIT_SNAPSHOTS_FULL", "有効期限が切れるまで最大10分", "板や期間"},
		{"AUDIT_INDEX_FULL", "サーバー管理者による確認", "10分"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/audit?action=site_name_update&limit=1", nil)
			response := httptest.NewRecorder()
			var handler adminHandler
			handler.auditFailure(response, request, &adminFailure{status: 503, code: tc.code})
			body := response.Body.String()
			if response.Code != 503 || !strings.Contains(body, tc.want) || strings.Contains(body, tc.absent) {
				t.Fatal(response.Code, body)
			}
			if tc.code == "AUDIT_CATCH_UP_PENDING" && !strings.Contains(body, `/audit?action=site_name_update&amp;limit=1`) {
				t.Fatal("retry discarded query", body)
			}
		})
	}
}
