// 保存済みの監査要約へ固定の日本語説明を付ける。設定値や現在値から過去の変更を推測しない。
package bootstrap

import (
	"slices"
	"strconv"
	"strings"
)

var auditFieldLabels = map[string]string{
	"board.categories":                "板のカテゴリー・並び順",
	"administrator.passkeys":          "登録済みのパスキー",
	"administrator.otp":               "認証アプリの登録",
	"administrator.login_policy":      "パスワードによるログインの可否",
	"site.minimum_reader_version":     "保存形式の対応バージョン",
	"global_rules":                    "掲示板全体の投稿規制",
	"waf.enabled":                     "WAFの有効・無効",
	"reading_access":                  "閲覧・管理画面の接続条件",
	"reading_access.admin.enabled":    "管理画面の接続制限",
	"board_rule":                      "投稿規制",
	"board_rule.enabled":              "投稿規制の有効・無効",
	"post.visibility":                 "レスの表示状態",
	"thread.state":                    "スレッドの状態",
	"operations.maintenance":          "保存の自動整理",
	"operations.reports":              "通報・自動通報",
	"operations.delivery":             "送信帯域",
	"operations.cache":                "圧縮・キャッシュ",
	"report.state":                    "依頼の対応状態",
	"report.assignee":                 "依頼の担当者",
	"report.answer":                   "依頼への回答",
	"case_retirement":                 "提出用ログの案件整理",
	"required_gc.originals":           "原本ログの自動整理",
	"network.config":                  "取得元・分類・上書きなどの回線分類設定",
	"network.rows":                    "自動取得した回線・国・VPNの分類表",
	"network.status":                  "回線分類の取得結果",
	"bump_watermark":                  "本文削除に伴うスレッド一覧順序の基準",
	"cap":                             "キャップの資格・条件",
	"cap.enabled":                     "キャップの有効・無効",
	"cap.revision":                    "キャップ資格の世代",
	"expiry_watermark":                "期限切れデータの整理基準時刻",
	"expired_control_records":         "期限切れの一時データ",
	"anon_policy.mode":                "匿名Cookieの利用条件",
	"abuse_guard":                     "反復投稿・不正フォームの対策",
	"global_posting_policy":           "掲示板全体の投稿制限",
	"local_rules":                     "板のローカルルール",
	"thread_settings":                 "レス数上限・終了レス",
	"site.posting_consent":            "利用規約・Cookieの説明",
	"site.terms_revision":             "利用規約の版",
	"site.name":                       "サイト名",
	"board.settings":                  "板の設定",
	"administrator.display_name":      "管理者の表示名",
	"administrator.password":          "パスワードの変更記録",
	"administrator.role":              "管理者の役割",
	"administrator.board_ids":         "管理者の担当板",
	"administrator.extra_permissions": "管理者の追加権限",
	"administrator.enabled":           "管理者の有効・無効",
	"administrator.auth_generation":   "ログイン資格の世代",
	"administrator":                   "管理者の登録情報",
	postingResourcesCollection:        "投稿受付の資源設定",
	"rate_policy":                     "投稿間隔・投稿数の制限",
	"anon_policy":                     "匿名Cookieの設定",
	"token_revocation":                "匿名Cookieの失効",
	"anon_policy.generation":          "匿名Cookieの世代",
	"board_directory":                 "板の登録",
	"board_directory.name":            "板の表示名",
	"board_directory.key":             "板の公開キー",
	"board_directory.aliases":         "板の旧キー",
	"board_directory.status":          "板の公開状態",
}

var auditDescriptions = map[string]string{
	"software_update_request":       "確認したコミットへの更新と再起動を要求しました。更新の完了を示す記録ではありません。結果はソフトウェア更新画面で確認してください。",
	"control_expiry_boundary":       "期限切れの一時データを整理する前に、基準時刻を保存しました。サーバーの時計が戻った際に規制などを誤って解除しないための内部処理です。保存期間の設定変更ではありません。",
	"expired_records_cleanup":       "再送の重複防止記録や規制に関する一時データのうち、期限切れのものを整理しました。この記録自体は、操作記録の削除や過去のログファイルの物理消去を示しません。",
	"thread_body_watermark":         "スレッド本文の保存領域を解放する処理に伴い、一覧の並び順に使う基準を保存しました。この記録だけでは本文削除の完了は確認できません。",
	"required_original_gc_progress": "原本ログの自動整理が進んだ段階を保存しました。この記録だけでは、整理全体の完了や削除件数は確認できません。",
	"cap_revoke":                    "キャップ資格を無効にしました。発行・変更などの記録は残ります。",
	"cap_reset":                     "キャップ鍵を再発行し、以前の鍵を無効にしました。",
	"anonymous_revoke":              "指定した匿名Cookieを利用できなくしました。利用者のブラウザーからCookieを消す操作ではありません。",
	"anonymous_revoke_all":          "それまでに発行した匿名Cookieをすべて利用できなくしました。利用者のブラウザーからCookieを消す操作ではありません。",

	"board_categories_update":           "板のカテゴリー分け・表示順を保存しました。",
	"administrator_password_changed":    "操作者本人のパスワードを変更しました。パスワードの内容は記録しません。",
	"administrator_passkey_register":    "本人確認後、管理者アカウントにパスキーを追加しました。",
	"administrator_passkey_remove":      "管理者アカウントからパスキーを削除しました。",
	"administrator_passkey_login":       "パスキーによるログインの認証結果を保存しました。",
	"administrator_passkey_reauth":      "パスキーによる本人の再確認を行いました。",
	"administrator_otp_register_finish": "認証アプリのコードを確認し、登録を完了しました。",
	"administrator_otp_remove":          "管理者アカウントの認証アプリ登録を解除しました。",
	"administrator_otp_policy":          "管理者アカウントのログイン方法を保存しました。",
	"administrator_otp_used":            "認証アプリのコードを照合し、同じコードの再使用を防ぐため使用済みとして保存しました。",
	"network_config":                    "取得元・カテゴリー・共通の上書きなど、回線分類の設定を保存しました。",
	"network_refresh":                   "自動分類表の更新結果を保存しました。",
	"network_fetch_failed":              "取得の失敗を記録しました。前回成功した分類表は維持します。",
	"site_name_update":                  "掲示板全体の表示名を保存しました。",
	"board_settings_update":             "対象の板の設定を保存しました。",
	"board_metadata_update":             "板の表示名・公開キーと、保持する旧キーを保存しました。",
	"operations_update":                 "保存整理・通報・配信などの運用設定を保存しました。",
	"reading_access_update":             "閲覧または管理画面の接続条件を保存しました。",
	"global_rules_update":               "掲示板全体に適用する投稿規制を追加・解除しました。",
	"waf_update":                        "HTTP要求の検査・頻度制限などのWAF設定を保存しました。",
	"post_evidence_query":               "レスの非公開記録を照会したことを記録しました。照会結果そのものは含みません。",
	"other_admin_operation":             "旧形式の監査要約で操作種別が省略され、元の操作ログからも種別を復元できなかった記録です。",
}

// describeAuditFields は記録済みの項目名を表示名へ変換する。項目ごとの差分を意味しない。
func describeAuditFields(fields []string) []string {
	labels := make([]string, 0, len(fields))
	for _, field := range fields {
		label := auditFieldLabels[field]
		if label == "" {
			label = "その他の記録項目"
		}
		if !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	return labels
}

// describeAuditOperation は固定の説明を優先し、CAPの開始を完了として表示しない。
func describeAuditOperation(entry AuditEntry, label string) string {
	if entry.Command != nil {
		target := "スレッド " + strconv.FormatUint(uint64(entry.Command.Thread), 10) + "・レス " + strconv.FormatUint(uint64(entry.Command.Post), 10)
		if entry.Command.Phase == "開始" {
			return target + "への操作を開始しました。完了は別の記録で確認してください。"
		}
		return target + "への操作の完了を記録しました。"
	}
	if description := auditDescriptions[entry.Action]; description != "" {
		return description
	}
	if purpose, ok := strings.CutPrefix(label, "保存形式を更新："); ok {
		return purpose + "に対応する保存形式へ更新しました。運用設定そのものの変更を示す記録ではありません。"
	}
	fields := describeAuditFields(entry.Fields)
	if len(fields) > 0 {
		return "操作の対象：" + strings.Join(fields, "、")
	}
	return label + "の記録です。"
}
