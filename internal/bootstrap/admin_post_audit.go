// 非公開レス照会の監査を板controlへ残す。現在値は一件に上書きし、履歴は既存WAL監査に従う。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type postEvidenceAudit struct {
	Actor   domain.ID   `json:"actor_id"`
	At      domain.Time `json:"at_ns"`
	Records []domain.ID `json:"record_ids"`
}

func validatePostEvidenceAudit(key string, old, next json.RawMessage) error {
	var value postEvidenceAudit
	if key != "latest" || strictjson.Decode(next, &value) != nil || value.Actor == (domain.ID{}) || value.At <= 0 || len(value.Records) < 1 || len(value.Records) > 100 {
		return store.ErrCorrupt
	}
	seen := map[domain.ID]bool{}
	for _, id := range value.Records {
		if id == (domain.ID{}) || seen[id] {
			return store.ErrCorrupt
		}
		seen[id] = true
	}
	if len(old) > 0 {
		var prior postEvidenceAudit
		if strictjson.Decode(old, &prior) != nil || value.At < prior.At {
			return store.ErrCorrupt
		}
	}
	return nil
}
