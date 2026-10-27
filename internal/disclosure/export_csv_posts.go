// 提出CSVの本文を一列にまとめ、本人の投稿へ接続情報と原本参照を対応付ける。
package disclosure

import "maps"

// exportCSVRows は正規化済み記録を公開投稿ごとの独立行へ展開する。入力と保存原本は変更しない。
func exportCSVRows(record map[string]any) []map[string]any {
	base := maps.Clone(record)
	content, ok := base["content"].(map[string]any)
	if ok {
		delete(base, "content")
	}
	flat := map[string]any{}
	if len(base) > 0 {
		flattenExportCSV("", base, flat)
	}

	if value, exists := content["body"]; exists {
		flat["public_body"] = value
	}
	if value, exists := content["public_title"]; exists {
		flat["public_title"] = value
	}
	posts, _ := content["public_posts"].([]any)
	if len(posts) == 0 {
		return []map[string]any{flat}
	}
	rows := make([]map[string]any, 0, len(posts))
	for _, raw := range posts {
		post := submissionObject(raw)
		row := maps.Clone(flat)
		if number, exists := post["number"]; exists {
			row["post_number"] = number
		}
		for _, key := range []string{"name", "mail"} {
			if value, exists := post[key]; exists {
				row["public_"+key] = value
			}
		}
		identity := submissionObject(post["identity"])
		for _, key := range []string{"date_text", "id", "slip", "trip", "cap"} {
			if value, exists := identity[key]; exists {
				row["public_"+key] = value
			}
		}
		rows = append(rows, row)
	}
	return rows
}
