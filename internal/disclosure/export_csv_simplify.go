// 提出用の選択済みデータから重複項目を除き、壁時計の日時を日本時間へ統一する。
package disclosure

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/domain"
)

// simplifyExportRecord はJSON正規化済みのコピーだけを編集する。保存原本は変更しない。
func simplifyExportRecord(row map[string]any) {
	for _, group := range []string{"identity", "time", "result"} {
		if values, ok := row[group].(map[string]any); ok {
			removeExportDuplicates(values, row)
		}
	}
	if values, ok := row["time"].(map[string]any); ok {
		if result, ok := row["result"].(map[string]any); ok {
			removeExportDuplicates(values, result)
		}
	}
	if connection, ok := row["connection"].(map[string]any); ok {
		removeExportDuplicates(connection, row)
		for _, group := range []string{"identity", "time", "request", "client", "environment"} {
			if values, ok := row[group].(map[string]any); ok {
				removeExportDuplicates(connection, values)
			}
		}
		// 名称だけが異なる保存済み解決結果も、一致する場合だけ利用者接続元へまとめる。
		if client, ok := row["client"].(map[string]any); ok {
			if reflect.DeepEqual(connection["client_source"], client["source"]) {
				delete(connection, "client_source")
			}
			if resolved, ok := connection["resolved"].(map[string]any); ok && reflect.DeepEqual(resolved["ip"], client["resolved_ip"]) && reflect.DeepEqual(resolved["port"], client["resolved_port"]) {
				delete(connection, "resolved")
			}
		}
	}
	normalizeExportTimes(row)
}

// removeExportDuplicates は同名かつ同値の項目だけを省き、異なる観測値は維持する。
func removeExportDuplicates(values, preferred map[string]any) {
	for key, value := range values {
		if key == "missing_fields" {
			continue
		}
		if other, exists := preferred[key]; exists && reflect.DeepEqual(value, other) {
			delete(values, key)
		}
	}
}

// normalizeExportTimes は配列内も含めて日時と欠測項目名を変換する。経過時間は変換しない。
func normalizeExportTimes(value any) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if strings.HasSuffix(key, "_utc") {
				if _, exists := node[strings.TrimSuffix(key, "_utc")+"_jst"]; exists {
					delete(node, key)
					continue
				}
			}
			if isExportTimestamp(key) {
				name := strings.TrimSuffix(key, "_ns") + "_jst"
				if child == nil {
					node[name] = nil
					delete(node, key)
					continue
				}
				var raw string
				switch number := child.(type) {
				case json.Number:
					raw = string(number)
				case string:
					raw = number
				}
				if raw != "" {
					if ns, e := strconv.ParseInt(raw, 10, 64); e == nil {
						node[name] = time.Unix(0, ns).In(domain.JST).Format(time.RFC3339Nano)
						delete(node, key)
						continue
					}
				}
			}
			if key == "field" {
				if field, ok := child.(string); ok && isExportTimestamp(field) {
					node[key] = strings.TrimSuffix(field, "_ns") + "_jst"
				}
			}
			normalizeExportTimes(child)
		}
	case []any:
		for _, child := range node {
			normalizeExportTimes(child)
		}
	}
}

func isExportTimestamp(key string) bool {
	return strings.HasSuffix(key, "_at_ns") || strings.HasSuffix(key, "_until_ns")
}
