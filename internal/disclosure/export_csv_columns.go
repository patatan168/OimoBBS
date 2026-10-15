// 提出CSVのカラムの意味。親の用途と末尾の項目名を合わせ、実カラムごとにREADMEへ記載する。
package disclosure

import "strings"

var csvColumnMeanings = map[string]string{
	"record_id": "この提出記録の識別ID", "source_record_id": "対応する元記録のID", "board_id": "対象板の固定ID", "thread_key": "スレッド番号", "operation_id": "投稿操作のID", "post_number": "投稿のレス番号",
	"committed_at_ns": "記録の確定時刻", "committed_at_utc": "記録確定時刻（UTC）", "committed_at_jst": "記録の確定時刻（日本時間）", "retention_until_ns": "記録の通常保存期限", "held_until_ns": "案件コピーの保全期限", "source_retention_until_ns": "元記録の保存期限",
	"source_event_sha256": "対応する元署名イベントのSHA-256", "decision_event_sha256": "受理・未受理判断イベントのSHA-256", "proposal_event_sha256": "元の投稿提案イベントのSHA-256", "source_control_seq": "元台帳の通し番号", "public_state": "現在の公開状態（unknownは未確認、not_acceptedは未受理）", "completeness": "記録の網羅性（partial/partial_observationは部分記録）", "preservation": "保存区分（ordinary_retentionは通常期限、case_holdは案件保全）",
	"operation_type": "投稿操作の種類", "record_kind": "提出記録の種類", "kind": "記録・投稿の種類", "outcome": "HTTP処理の観測結果", "attempt_result": "投稿の受理判断", "accepted_operation_id": "受理された操作ID", "decision_at_ns": "受理判断が記録された時刻", "recovered": "復旧処理で確定したか", "thread_seq": "スレッド内の操作通し番号", "thread_frame_sha256": "確定スレッドframeのSHA-256", "planned_http_status": "投稿判断時の予定HTTP状態コード（未記録ならnull）", "response_event_ref": "対応するHTTP応答記録", "response": "対応するHTTP応答の観測",
	"received_at_ns": "要求受付時刻", "received_at_utc": "要求受付時刻（UTC）", "received_at_jst": "要求受付時刻（日本時間）", "body_completed_at_ns": "要求本文の受信完了時刻", "prepared_at_ns": "投稿準備時刻（未記録ならnull）", "finished_at_ns": "HTTP handler終了の観測時刻", "finished_at_utc": "HTTP handler終了時刻（UTC）", "finished_at_jst": "HTTP handler終了時刻（日本時間）", "response_finished_at_ns": "対応するHTTP応答の終了時刻", "monotonic_elapsed_ns": "単調時計で測った経過時間（ナノ秒）", "clock_status": "時計観測の状態", "clock_source": "保存された時計情報の出所", "clock_offset_ms": "時計のずれ（ミリ秒、未確認ならnull）", "clock_observed_at_ns": "時計の状態を観測した時刻",
	"ip": "IPアドレス", "port": "TCPポート番号", "resolved_ip": "保存時の解決済み利用者IP", "resolved_port": "保存時の解決済み利用者ポート", "source": "利用者接続元の判定根拠", "client_source": "利用者接続元の判定根拠", "transport": "接続方式", "http_version": "HTTPプロトコルの版", "tls_version": "TLSプロトコル番号（十進表記、771=TLS1.2、772=TLS1.3）", "tls_cipher_suite": "TLS暗号スイート番号（十進表記）", "sni": "TLSで受信したサーバー名", "proxy_profile_id": "認証プロキシ設定のID", "proxy_config_revision": "保存時のプロキシ設定版", "verified_proxy_chain": "認証済みプロキシ経路の一覧", "reported_chain": "申告された転送経路（未保存ならnull）", "reported_headers": "未検証の転送ヘッダ一覧", "reported_headers_verified": "申告ヘッダの検証有無（falseは未検証）", "origin_endpoint": "認証edgeが受信した利用者側の宛先", "connection": "接続観測（nullなら未記録）",
	"method": "HTTPメソッド", "route": "保存済みの経路分類（URLの秘密queryは含まない）", "canonical_host": "照合済みの公開ホスト名", "board_alias_used": "使われた板の別名（未記録ならnull）", "declared_charset": "要求が宣言した文字コード", "body_bytes": "受信本文のbytes数", "selected_headers": "許可リストにある要求ヘッダの一覧", "header_capture_status": "要求ヘッダの取得状態", "parsed_header_bytes": "HTTPパーサが取得したヘッダbytes数", "user_agent": "受信User-Agent（未検証の申告値）", "user_agent_capture_status": "User-Agentの取得状態", "http_status": "観測したHTTP状態コード（未観測ならnull）", "written_bytes": "HTTP handlerが書き込めたbytes数", "write_failed": "応答の書き込みに失敗したか", "request_canceled": "要求が取り消されたか", "finish_stage": "観測を終了した処理段階（handler_return等）",
	"site_id": "サイトID", "site_instance_id": "永続サーバーinstanceのID", "process_boot_id": "プロセス起動ごとのID", "connection_id": "TCP接続のID", "request_id": "HTTP要求のID", "schema": "保存された観測形式の版", "evidence_schema": "受理時に保存したcapture形式の版", "server_build_id": "保存時のサーバービルド識別子", "text_codec_version": "保存時の文字コード処理の版", "renderer_profile": "保存時の公開表示処理の版", "clock_policy_revision": "時計方針の保存版（未記録ならnull）", "proxy_policy_revision": "保存時のプロキシ方針の版",
	"name": "投稿時の名前（秘密除去済み）", "mail": "投稿時のメール欄", "title": "投稿入力の件名", "body": "投稿入力の本文（コマンド展開前）", "body_sha256": "投稿入力本文のSHA-256", "public_title": "受理時に確定した公開件名", "public_title_missing_reason": "公開件名の欠測理由", "public_posts": "受理時に確定した公開投稿の一覧", "dat_base64": "受理時のDAT元bytesをbase64化した値", "dat_sha256": "受理時のDAT元bytesのSHA-256",
	"anon_subject_hmac": "匿名主体の秘密なしHMAC識別子（本人確認の証明ではない）", "hmac_key_id": "匿名主体HMACの鍵ID（未保存ならnull）", "cap_id": "認証されたキャップのID", "cap_revision": "保存時のキャップ設定版", "token_validation": "保存時の匿名資格検証結果", "subject_hmac": "保存済み匿名主体のHMAC", "rule_ids": "適用された受理枠ルールID一覧", "key_id": "該当用途の鍵ID", "id": "該当資格・設定のID", "revision": "該当設定の保存版", "display_name": "保存時のキャップ表示名", "cost": "受理枠で消費した数量", "rule_id": "該当する受理枠ルールのID", "rate_key": "受理枠で使用した鍵の対応", "overrides": "適用された規制除外の対応", "token": "秘密を除いた匿名資格情報", "cap": "秘密を除いたキャップ情報", "optional_http": "関連HTTP観測と元署名対応の一覧", "missing_fields": "欠測項目fieldと理由reasonの一覧", "connection_missing_reason": "接続観測がない理由",
}

// csvColumnMeaning は親階層の意味も示す。設定版の枝は保存当時の値であることを明記する。
func csvColumnMeaning(path string) string {
	parts := strings.Split(path, ".")
	leaf := parts[len(parts)-1]
	meaning := csvColumnMeanings[leaf]
	if meaning == "" && strings.HasSuffix(leaf, "_jst") {
		meaning = csvColumnMeanings[strings.TrimSuffix(leaf, "_jst")+"_ns"]
		if meaning != "" {
			meaning += "（日本時間）"
		}
	}
	if strings.Contains(path, "policy_versions.") {
		meaning = "受理時に適用した設定の保存版（" + leaf + "）"
	}
	if meaning == "" {
		meaning = "保存された「" + leaf + "」の値"
	}
	groups := map[string]string{"connection": "接続観測", "client": "利用者接続元", "request": "HTTP要求", "identity": "要求・操作の識別情報", "time": "要求の時刻", "result": "投稿・応答の結果", "environment": "保存時の処理環境", "content": "投稿内容", "principal": "投稿資格"}
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
	case strings.Contains(path, ".resolved."):
		meaning += "（保存時の利用者接続元の解決結果）"
	case strings.Contains(path, ".origin_endpoint."):
		meaning += "（認証edge側の宛先socket）"
	}
	return meaning
}
