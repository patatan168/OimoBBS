// 提出CSVのカラムの意味。親の用途と末尾の項目名を合わせ、実カラムごとにREADMEへ記載する。
package disclosure

import "strings"

var csvColumnMeanings = map[string]string{
	"reverse_dns":                  "投稿時の接続元IPに対するDNS観測（本人・所属の証明ではない）",
	"names":                        "逆引きで取得したPTRホスト名の一覧（未確認の名前も含む）",
	"confirmed_name":               "正引きが接続元IPと一致したホスト名（未確認なら空文字）",
	"observed_at_ns":               "DNS結果の観測時刻（キャッシュ利用時は元の照会時刻）",
	"thread_key":                   "スレッド番号",
	"board_key":                    "投稿時に使用された板キー（保存済みの要求値。板のURL別名を含む）",
	"post_number":                  "投稿のレス番号",
	"post_numbers":                 "受理時に確定した投稿のレス番号一覧",
	"committed_at_ns":              "記録の確定時刻",
	"source_event_sha256":          "対応する元署名イベントのSHA-256",
	"decision_event_sha256":        "受理・未受理判断イベントのSHA-256",
	"proposal_event_sha256":        "元の投稿提案イベントのSHA-256",
	"completeness":                 "記録の網羅性（partial/partial_observationは部分記録）",
	"record_kind":                  "提出記録の種類",
	"kind":                         "記録・投稿の種類",
	"outcome":                      "HTTP処理の観測結果",
	"attempt_result":               "投稿の受理判断",
	"response":                     "対応するHTTP応答の観測",
	"received_at_ns":               "要求受付時刻",
	"finished_at_ns":               "HTTP handler終了の観測時刻",
	"response_finished_at_ns":      "同じHTTP要求に対応付いたhandler終了の観測時刻（送信完了や相手先の受領時刻ではない）",
	"ip":                           "IPアドレス",
	"port":                         "TCPポート番号",
	"resolved_ip":                  "保存時の解決済み利用者IP",
	"resolved_port":                "保存時の解決済み利用者ポート",
	"connection":                   "接続観測（nullなら未記録）",
	"canonical_host":               "照合済みの公開ホスト名",
	"user_agent":                   "受信User-Agent（未検証の申告値）",
	"user_agent_capture_status":    "User-Agentの取得状態",
	"http_status":                  "観測したHTTP状態コード（未観測ならnull）",
	"name":                         "投稿時の名前（秘密除去済み）",
	"mail":                         "投稿時のメール欄",
	"title":                        "投稿入力の件名",
	"public_body":                  "投稿者本人の本文（正規化・秘密除去後の受理時記録）",
	"public_title":                 "受理時に確定した公開件名",
	"number":                       "受理時に確定した公開投稿のレス番号",
	"date_text":                    "受理時に確定した公開投稿の日時表示",
	"slip":                         "公開投稿のSLIP表示",
	"trip":                         "公開投稿のトリップ表示",
	"public_name":                  "受理時に確定した公開名",
	"public_mail":                  "受理時に確定した公開メール欄",
	"public_date_text":             "受理時に確定した公開投稿の日時表示",
	"public_id":                    "公開投稿のID",
	"public_slip":                  "公開投稿のSLIP表示",
	"public_trip":                  "公開投稿のトリップ表示",
	"public_cap":                   "公開キャップ表示",
	"id":                           "公開投稿のID",
	"cap":                          "公開キャップ表示",
	"response_http_status":         "同じ投稿要求と照合できたHTTP応答の状態コード（未観測ならnull）",
	"response_outcome":             "同じ投稿要求に対応するHTTP処理の観測結果",
	"response_source_event_sha256": "同じ投稿要求に対応するHTTP応答の元署名イベントのSHA-256",
	"missing_fields":               "欠測項目fieldと理由reasonの一覧",
	"connection_missing_reason":    "接続観測がない理由",
}

// csvColumnMeaning は現在の提出項目について、親階層の用途と値の意味を示す。
func csvColumnMeaning(path string) string {
	if path == "cookie.id" {
		return "検証済み匿名Cookie由来の照合用HMAC。本人確認や同一人物の証明ではなく、Cookieの削除・再発行で変わる"
	}
	if path == "cookie.status" {
		return "投稿時の匿名Cookie検証結果。validだけが検証済みで、未検証・未記録ならIDはnull"
	}
	parts := strings.Split(path, ".")
	leaf := parts[len(parts)-1]
	meaning := csvColumnMeanings[leaf]

	if strings.Contains(path, "reverse_dns.") && leaf == "status" {
		meaning = "DNS確認状態（confirmed=正引き一致、absent=PTRなし、mismatch=不整合、unchecked=一時障害などで未確認）"
	}
	if meaning == "" && strings.HasSuffix(leaf, "_jst") {
		meaning = csvColumnMeanings[strings.TrimSuffix(leaf, "_jst")+"_ns"]
		if meaning != "" {
			meaning += "（日本時間）"
		}
	}
	if meaning == "" {
		meaning = "保存された「" + leaf + "」の値"
	}
	groups := map[string]string{"connection": "接続観測", "client": "利用者接続元", "request": "HTTP要求", "identity": "投稿対象", "time": "要求の時刻", "result": "投稿・応答の結果", "content": "投稿内容"}
	if len(parts) > 1 {
		if group := groups[parts[0]]; group != "" {
			meaning = group + "：" + meaning
		}
	}
	switch {
	case strings.Contains(path, ".peer."):
		meaning += "（サーバーから見た直近の接続相手。プロキシの場合はそのプロキシ）"
	case strings.Contains(path, ".local."):
		meaning += "（サーバー側の受信socket）"
	}
	return meaning
}
