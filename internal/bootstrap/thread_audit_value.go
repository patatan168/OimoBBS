// 日別監査へ渡すスレッド操作要約をtag付き固定型として検査する。
package bootstrap

import (
	"encoding/json"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"time"
)

type threadAuditStored struct {
	ID      domain.ID       `json:"id"`
	Kind    string          `json:"kind"`
	Board   domain.ID       `json:"board_id"`
	Thread  domain.U64      `json:"thread_key"`
	At      domain.Time     `json:"committed_at_ns"`
	Expires domain.Time     `json:"expires_at_ns"`
	Payload store.PackAudit `json:"payload"`
}

func isThreadAudit(raw json.RawMessage) bool {
	var tag struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(raw, &tag) == nil && tag.Kind == "thread_summary"
}

func validateThreadAuditValue(owner domain.ID, kind, day, key string, raw json.RawMessage) error {
	var v threadAuditStored
	if strictjson.Decode(raw, &v) != nil {
		return store.ErrCorrupt
	}
	a := v.Payload
	if kind != "board" || key != v.ID.String() || v.ID == (domain.ID{}) || v.Kind != "thread_summary" || v.Board != owner || v.Thread == 0 || v.At <= 0 || v.At > domain.Time(math.MaxInt64)-domain.Time(auditRetention) || v.Expires != v.At+domain.Time(auditRetention) || time.Unix(0, int64(v.At)).UTC().Format("20060102") != day || a.ID != v.ID || a.Committed != v.At || a.Expires != v.Expires || a.Seq == 0 || a.Actor.Validate() != nil || a.Versions.Site == 0 || a.Versions.Board == 0 || a.Ranges == nil || len(a.Ranges) > 256 {
		return store.ErrCorrupt
	}
	if !slices.Contains([]string{"create", "append", "redact", "stop", "archive", "move_link", "hide", "update_policy"}, a.Type) {
		return store.ErrCorrupt
	}
	if a.Type == "create" {
		if a.Seq != 1 || a.Versions.Thread != 0 {
			return store.ErrCorrupt
		}
	} else if a.Versions.Thread == 0 {
		return store.ErrCorrupt
	}
	if (a.Type == "create" || a.Type == "append") && a.Actor.Kind != "anonymous" && a.Actor.Kind != "cap" {
		return store.ErrCorrupt
	}
	var last uint32
	for _, r := range a.Ranges {
		if r.First == 0 || r.First > r.Last || r.First <= last {
			return store.ErrCorrupt
		}
		last = r.Last
	}
	modifies := slices.Contains([]string{"create", "append", "redact", "stop"}, a.Type)
	if modifies != (len(a.Ranges) > 0) {
		return store.ErrCorrupt
	}
	return nil
}

// auditStoredIdentity はtagごとのID/期限を返し、一般管理要約へthreadの私的項目を混ぜない。
func auditStoredIdentity(raw json.RawMessage) (domain.ID, domain.Time, error) {
	if isThreadAudit(raw) {
		var v threadAuditStored
		e := strictjson.Decode(raw, &v)
		return v.ID, v.Expires, e
	}
	var v auditStoredEntry
	e := strictjson.Decode(raw, &v)
	return v.Summary.ID, v.Expires, e
}
