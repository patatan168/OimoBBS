// 提出・照会の共通許可リスト。署名原本を変更せず、機関へ渡す記録から内部処理情報を除く。
package disclosure

import (
	"bytes"
	"encoding/json"
)

// SubmissionRecords は選択済み記録の独立コピーから、提出先の照合に使う項目だけを返す。
// 日時は日本時間に統一する。未選択・未保存の情報や現在設定から値を補わない。
func SubmissionRecords(rows []map[string]any) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value map[string]any
		if err = decoder.Decode(&value); err != nil {
			return nil, err
		}
		out := submissionRecord(value)
		simplifyExportRecord(out)
		result = append(result, out)
	}
	return result, nil
}

func submissionPick(source map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, key := range keys {
		if v, ok := source[key]; ok {
			out[key] = v
		}
	}
	return out
}
func submissionObject(v any) map[string]any { m, _ := v.(map[string]any); return m }
func submissionGroup(out, source map[string]any, name string, keys ...string) {
	if v, exists := source[name]; exists {
		if v == nil {
			out[name] = nil
			return
		}
		out[name] = submissionPick(submissionObject(v), keys...)
	}
}

// submissionGaps は残す列の欠測理由だけを維持し、削除した内部列の理由も出力しない。
func submissionGaps(out, source map[string]any, keys ...string) {
	fields, _ := source["missing_fields"].([]any)
	var kept []any
	for _, v := range fields {
		m := submissionObject(v)
		for _, key := range keys {
			if m["field"] == key {
				kept = append(kept, submissionPick(m, "field", "reason"))
				break
			}
		}
	}
	if len(kept) > 0 {
		out["missing_fields"] = kept
	}
}

func submissionRecord(row map[string]any) map[string]any {
	submissionConnectionContext(row)
	out := submissionPick(row, "thread_key", "post_number", "committed_at_ns", "received_at_ns", "finished_at_ns", "record_kind", "kind", "route", "outcome", "http_status", "attempt_result", "source_event_sha256", "proposal_event_sha256", "decision_event_sha256", "completeness", "connection_missing_reason")
	submissionGaps(out, row, "http_status")

	submissionGroup(out, row, "cookie", "id", "status")
	submissionGroup(out, row, "time", "received_at_ns", "response_finished_at_ns")
	submissionGroup(out, row, "result", "attempt_result")
	submissionResponse(out, row)
	submissionRequest(out, row)
	submissionClient(out, row)
	submissionConnection(out, row)
	submissionContent(out, row)

	return out
}

// submissionRequest は保存済みの投稿先から板キーを取り出し、欠測理由も同じ列名へそろえる。
func submissionRequest(out, row map[string]any) {
	submissionGroup(out, row, "request", "canonical_host")
	if request := submissionObject(row["request"]); request != nil {
		if key, exists := request["board_alias_used"]; exists {
			out["board_key"] = key
		}
		gaps := map[string]any{}
		submissionGaps(gaps, request, "board_alias_used")
		fields, _ := gaps["missing_fields"].([]any)
		missing, _ := out["missing_fields"].([]any)
		for _, gap := range fields {
			field := submissionObject(gap)
			field["field"] = "board_key"
			missing = append(missing, field)
		}
		if len(missing) > 0 {
			out["missing_fields"] = missing
		}
	}
	if request := submissionObject(out["request"]); request != nil && len(request) == 0 {
		delete(out, "request")
	}
}

// submissionAgents は保存されたUser-Agentの表示値だけを返す。転送ヘッダや他の申告値を混ぜない。
func submissionAgents(observation map[string]any) ([]any, bool) {
	headers, _ := observation["selected_headers"].([]any)
	for _, header := range headers {
		h := submissionObject(header)
		if h["name"] != "User-Agent" {
			continue
		}
		values, _ := h["values"].([]any)
		out := make([]any, 0, len(values))
		for _, value := range values {
			if text, ok := submissionObject(value)["display"].(string); ok {
				out = append(out, text)
			}
		}
		return out, true
	}
	return nil, false
}

// submissionAgentValue はHTTPパーサの表示値だけを使い、ヘッダの元bytes表現を提出しない。
func submissionAgentValue(value any) any {
	if v := submissionObject(value); v != nil {
		return v["display"]
	}
	return value
}

// submissionConnectionContext は未受理記録の保存済み解決先を、受理記録と同じ提出列へそろえる。
func submissionConnectionContext(row map[string]any) {
	obs := submissionObject(row["connection"])
	if obs == nil {
		return
	}
	resolved := submissionObject(obs["resolved"])
	if resolved != nil && submissionObject(row["client"]) == nil {
		row["client"] = map[string]any{"resolved_ip": resolved["ip"], "resolved_port": resolved["port"], "reverse_dns": obs["reverse_dns"]}
	}
	if _, exists := row["request"]; !exists {
		if _, observed := obs["canonical_host"]; observed {
			row["request"] = submissionPick(obs, "canonical_host", "board_alias_used")
		}
	}
}

// submissionClient は保存済みの利用者IP・ポート・DNS結果だけを選ぶ。
func submissionClient(out, row map[string]any) {
	if client, ok := row["client"]; ok {
		if client == nil {
			out["client"] = nil
		} else {
			source := submissionObject(client)
			v := submissionPick(source, "resolved_ip", "resolved_port")
			submissionGroup(v, source, "reverse_dns", "names", "confirmed_name", "status", "observed_at_ns")
			submissionGaps(v, source, "reverse_dns")
			out["client"] = v
		}
	}

}

// submissionConnection はUser-Agentを残し、内部プロキシの接続先を重ねない。
func submissionConnection(out, row map[string]any) {
	if raw, ok := row["connection"]; ok {
		if raw == nil {
			out["connection"] = nil
		} else {
			source := submissionObject(raw)
			v := submissionPick(source, "user_agent_capture_status")
			if value, exists := source["user_agent"]; exists {
				v["user_agent"] = submissionAgentValue(value)
			}
			// 利用者IPが別に保存されている受理記録へ、内部プロキシのpeerを重ねて提出しない。
			if submissionObject(row["client"]) == nil {
				for _, name := range []string{"peer", "local"} {
					submissionGroup(v, source, name, "ip", "port")
				}
			}
			if agent, exists := submissionAgents(source); exists {
				v["user_agent"] = agent
			}
			if len(v) > 0 {
				out["connection"] = v
			}
		}
	}

}

// submissionContent は秘密除去済み入力と本人の公開投稿だけを返す。自動投稿・DAT元bytes・内部hashは除く。
func submissionContent(out, row map[string]any) {
	if source := submissionObject(row["content"]); source != nil {
		v := submissionPick(source, "name", "mail", "title", "body", "public_title")
		if posts, ok := source["public_posts"].([]any); ok {
			values := make([]any, 0, len(posts))
			for _, post := range posts {
				p := submissionObject(post)
				if p["kind"] == "system" {
					continue
				}
				item := submissionPick(p, "number", "name", "mail", "body")
				submissionGroup(item, p, "identity", "date_text", "id", "slip", "trip", "cap")
				values = append(values, item)
			}
			v["public_posts"] = values
		}
		out["content"] = v
	} else if v, ok := row["content"]; ok && v == nil {
		out["content"] = nil
	}

}

// submissionResponse は同一要求と照合済みの応答だけを列にし、HTTP原本一覧は提出しない。
// 終了時刻はtime側に保持し、UA・接続元・受付時刻を応答側へ重ねない。
func submissionResponse(out, row map[string]any) {
	response := submissionObject(submissionObject(row["result"])["response"])
	for _, key := range []string{"source_event_sha256", "http_status", "outcome"} {
		if value, exists := response[key]; exists {
			out["response_"+key] = value
		}
	}
	gaps := map[string]any{}
	submissionGaps(gaps, response, "http_status")
	fields, _ := gaps["missing_fields"].([]any)
	missing, _ := out["missing_fields"].([]any)
	for _, field := range fields {
		gap := submissionObject(field)
		gap["field"] = "response_http_status"
		missing = append(missing, gap)
	}
	if len(missing) > 0 {
		out["missing_fields"] = missing
	}
}
