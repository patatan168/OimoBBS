// 日末署名を既存の板controlへ固定し、原本の日別列欠落・巻戻りを起動前に検査する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"time"
)

// decodeRequiredCheckpointAnchor は板controlの行keyと完全型の日末署名を照合する。
// 鍵検証と原本の存在確認は起動前検査で別途行う。
func decodeRequiredCheckpointAnchor(day string, raw json.RawMessage) (evidence.Event, evidence.JournalCheckpoint, error) {
	var event evidence.Event
	if e := strictjson.Decode(raw, &event); e != nil {
		return event, evidence.JournalCheckpoint{}, e
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(event.Payload)
	if e != nil {
		return event, evidence.JournalCheckpoint{}, e
	}
	p, e := evidence.DecodeJournalCheckpoint(payload)
	if e != nil {
		return event, p, e
	}
	if event.Kind != "journal_checkpoint" || fmt.Sprint(p.Day) != day || event.PreviousSHA != p.TerminalSHA {
		return event, p, store.ErrCorrupt
	}
	return event, p, nil
}

// validateRequiredCheckpointAnchor は同じ所有者/日の確認境界だけを単調に更新する。
func validateRequiredCheckpointAnchor(day string, old, next json.RawMessage) error {
	_, p, e := decodeRequiredCheckpointAnchor(day, next)
	if e != nil || len(old) == 0 {
		return e
	}
	_, prior, e := decodeRequiredCheckpointAnchor(day, old)
	if e != nil {
		return e
	}
	if p.Owner != prior.Owner || p.Sequence <= prior.Sequence || p.At < prior.At {
		return store.ErrCorrupt
	}
	return nil
}

// inspectRequiredCheckpointAnchors は独立した板controlの境界を原本へ照合する。
// 原本が丸ごと消えた場合も空列で補完せず、変更前に欠落として拒否する。
func inspectRequiredCheckpointAnchors(cfg Config, site siteState, b persistedBoard, key ed25519.PrivateKey) error {
	for rowKey, row := range b.control.Rows {
		if !strings.HasPrefix(rowKey, "evidence_checkpoint:") {
			continue
		}
		day := rowKey[len("evidence_checkpoint:"):]
		event, p, e := decodeRequiredCheckpointAnchor(day, row.Value)
		if e != nil {
			return e
		}
		if site.MinimumReader < 55 || p.Owner != b.info.ID {
			return store.ErrCorrupt
		}
		if _, e = evidence.VerifyJournalCheckpoint(event, key.Public().(ed25519.PublicKey)); e != nil {
			return e
		}
		if domain.Time(time.Now().UnixNano()) < p.At {
			return evidence.ErrRetirementClock
		}
		if e = inspectRequiredCheckpointSource(cfg, b.info.ID, day, event, p, key); e != nil {
			return e
		}
	}
	return nil
}

// inspectBoardCheckpointRows は期限なしの日別参照を作成jobの所有者へ束縛する。
func inspectBoardCheckpointRows(state store.ControlState, owner domain.ID) (int, error) {
	count := 0
	for key, row := range state.Rows {
		day, ok := strings.CutPrefix(key, "evidence_checkpoint:")
		if !ok {
			continue
		}
		_, p, e := decodeRequiredCheckpointAnchor(day, row.Value)
		if e != nil {
			return 0, e
		}
		if p.Owner != owner || row.Expires != nil {
			return 0, store.ErrCorrupt
		}
		count++
	}
	return count, nil
}

// inspectRequiredCheckpointSource は検証済み日別列に固定した署名が現存するか確認する。
func inspectRequiredCheckpointSource(cfg Config, owner domain.ID, day string, event evidence.Event, p evidence.JournalCheckpoint, key ed25519.PrivateKey) error {
	found := false
	path := filepath.Join(cfg.DataDir, "evidence", owner.String(), day)
	_, e := evidence.VisitJournalReadOnly(path, owner, uint64(p.Day), 10, key, app.PostingValidator(strictjson.Validate), func(entry evidence.Entry) error {
		if entry.Event.RecordID == event.RecordID && entry.Event.EventSHA == event.EventSHA {
			found = true
		}
		return nil
	})
	if e != nil || !found {
		return fmt.Errorf("%w: required journal checkpoint mismatch", app.ErrEvidenceGap)
	}
	return nil
}
