// 管理操作の許可済み要約を所有者・UTC日別controlへ重複なく同期保存する。
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const auditRetention = 180 * 24 * time.Hour

// 保存型には要求HMACや元mutationを持たせない。期限は元の確定時刻から固定する。
type auditStoredEntry struct {
	Schema  uint32      `json:"schema_version"`
	Kind    string      `json:"kind"`
	Expires domain.Time `json:"expires_at_ns"`
	Summary AuditEntry  `json:"summary"`
}
type auditOrigin struct {
	Schema    uint32    `json:"schema_version"`
	Owner     domain.ID `json:"owner_id"`
	OwnerKind string    `json:"owner_kind"`
	Day       string    `json:"utc_day"`
}

// auditInitial は所有者と日付から常に同じ初期frameを作る。日別ディレクトリ自体が作成intent。
// 空ファイルや途中prefixを復旧しても、乱数・再起動時刻で初期内容を変えない。
func auditInitial(owner domain.ID, kind, day string) (store.Header, []byte, error) {
	at, e := time.Parse("20060102", day)
	if e != nil || at.Year() < 1970 || at.Year() > 2261 {
		return store.Header{}, nil, store.ErrCorrupt
	}
	key, _ := strconv.ParseUint(day, 10, 64)
	hash := sha256.Sum256([]byte("oimo/audit-origin/v1/" + owner.String() + "/" + kind + "/" + day))
	var id domain.ID
	copy(id[:], hash[:16])
	frame, e := controlFrame(store.ControlState{}, id, domain.Time(at.UnixNano()), "audit_origin", []store.Mutation{mutation("import_receipt", "origin", auditOrigin{1, owner, kind, day}, nil)}, []string{})
	return store.Header{Kind: 4, Owner: owner, Key: key, Generation: 1}, frame, e
}

// auditValueValidator は追記専用の完全型と所有先、固定期限、許可された項目名を検査する。
func auditValueValidator(owner domain.ID, kind, day string) store.ValueValidator {
	return func(collection, key string, old, next json.RawMessage) error {
		if collection == "import_receipt" && strings.HasPrefix(key, "thread:") {
			if len(old) != 0 || kind != "board" {
				return store.ErrCorrupt
			}
			var v threadAuditTransfer
			if strictjson.Decode(next, &v) != nil || v.shape() != nil || v.Board != owner || key != fmt.Sprintf("thread:%d:%s", v.Thread, v.Deletion) {
				return store.ErrCorrupt
			}
			found := false
			for _, d := range v.Days {
				if d.Day == day {
					found = true
				}
			}
			if !found {
				return store.ErrCorrupt
			}
			return nil
		}
		if collection == "import_receipt" && key == "source" {
			return validateAuditTransfer(owner, kind, day, old, next)
		}
		if len(old) != 0 {
			return store.ErrCorrupt
		}
		if collection == "import_receipt" && key == "origin" {
			var v auditOrigin
			if e := strictjson.Decode(next, &v); e != nil {
				return e
			}
			if v != (auditOrigin{1, owner, kind, day}) {
				return store.ErrCorrupt
			}
			return nil
		}
		if collection != "audit_entry" {
			return store.ErrCorrupt
		}
		if isThreadAudit(next) {
			return validateThreadAuditValue(owner, kind, day, key, next)
		}
		var v auditStoredEntry
		if e := strictjson.Decode(next, &v); e != nil {
			return e
		}
		a := v.Summary
		at, e := time.Parse(time.RFC3339Nano, a.Committed)
		fields, known := auditActions[a.Action]
		if e != nil || at.UTC().Format(time.RFC3339Nano) != a.Committed || at.UTC().Format("20060102") != day || at.UnixNano() > math.MaxInt64-int64(auditRetention) {
			return store.ErrCorrupt
		}
		if v.Schema != 1 || v.Kind != "control_summary" || v.Expires != domain.Time(at.UnixNano()+int64(auditRetention)) || a.ID.String() != key || a.Owner != owner || a.OwnerKind != kind || a.Sequence == 0 || !known || a.Fields == nil || !slices.Equal(a.Fields, fields) || a.Targets == nil || len(a.Targets) > 256 {
			return store.ErrCorrupt
		}
		if (kind == "board" && (a.Board == nil || *a.Board != owner)) || (kind == "site" && a.Board != nil) || (kind != "site" && kind != "board") {
			return store.ErrCorrupt
		}
		if (a.ActorKind == "system" && a.ActorID != nil) || ((a.ActorKind == "admin" || a.ActorKind == "cap") && a.ActorID == nil) || (a.ActorKind != "system" && a.ActorKind != "admin" && a.ActorKind != "cap") {
			return store.ErrCorrupt
		}
		if a.ActorKind == "cap" && !strings.HasPrefix(a.Action, "cap_command_") {
			return store.ErrCorrupt
		}
		if a.Command != nil {
			c := a.Command
			if a.ActorKind != "cap" || c.Thread == 0 || c.Post == 0 || c.Phase != "開始" && c.Phase != "完了" {
				return store.ErrCorrupt
			}
			command := strings.TrimSuffix(strings.TrimPrefix(a.Action, "cap_command_"), "_applied")
			if command == "ban" {
				if c.Duration != "permanent" {
					parsed, _, err := parseCapCommand(fmt.Sprintf(">>1 !ban %s", c.Duration))
					if err != nil || parsed.Kind != "ban" || capCommandDuration(parsed) != c.Duration {
						return store.ErrCorrupt
					}
				}
			} else if c.Duration != command {
				return store.ErrCorrupt
			}
			if (c.Phase == "完了") != strings.HasSuffix(a.Action, "_applied") {
				return store.ErrCorrupt
			}
		}
		for _, target := range a.Targets {
			raw, _ := json.Marshal(target)
			var id domain.ID
			if json.Unmarshal(raw, &id) == nil {
				continue
			}
			var key domain.U64
			if json.Unmarshal(raw, &key) != nil || key == 0 {
				return store.ErrCorrupt
			}
		}
		return nil
	}
}

// auditSink は同時に一つの日別fileだけを開く。保存失敗時は索引と走査位置を進めない。
type auditSink struct {
	root, path string
	remember   func(string, *store.ControlLog) error
	log        *store.ControlLog
}

func (s *auditSink) close() error {
	if s.log == nil {
		return nil
	}
	var e error
	if s.remember != nil {
		e = s.remember(s.path, s.log)
	}
	e = errors.Join(e, s.log.Close())
	s.log = nil
	s.path = ""
	return e
}
func (s *auditSink) put(entry AuditEntry) error {
	at, e := time.Parse(time.RFC3339Nano, entry.Committed)
	if e != nil {
		return e
	}
	day := at.UTC().Format("20060102")
	if e = s.open(entry.Owner, entry.OwnerKind, day); e != nil {
		return e
	}
	value := auditStoredEntry{1, "control_summary", domain.Time(at.UnixNano() + int64(auditRetention)), entry}
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	state := s.log.State()
	if prior, ok := state.Rows["audit_entry:"+entry.ID.String()]; ok {
		if !bytes.Equal(prior.Value, raw) || prior.Expires == nil || *prior.Expires != value.Expires {
			return store.ErrCorrupt
		}
		return nil
	}
	frame, e := controlFrame(state, entry.ID, domain.Time(at.UnixNano()), "audit_import", []store.Mutation{mutation("audit_entry", entry.ID.String(), value, &value.Expires)}, []string{})
	if e != nil {
		return e
	}
	result := s.log.Append(frame)
	if result.Status != store.Durable {
		return errors.Join(errors.New("audit import not durable"), result.Err)
	}
	return nil
}

// open は日別所有先を検証・復旧し、一度に一つのfileだけを所有する。
func (s *auditSink) open(owner domain.ID, kind, day string) error {
	var e error
	ownerDir := filepath.Join(s.root, owner.String())
	path := filepath.Join(ownerDir, day)
	if s.path != path {
		if e = s.close(); e != nil {
			return e
		}
		if e = privatePath(s.root, true); e != nil {
			return e
		}
		if _, e = os.Lstat(ownerDir); os.IsNotExist(e) {
			e = makePrivateDir(ownerDir)
		}
		if e != nil {
			return e
		}
		if e = privatePath(ownerDir, true); e != nil {
			return e
		}
		// 前回mkdir後に親Syncだけ失敗していても、この呼出しで確定する。
		if e = store.SyncDirectory(s.root); e != nil {
			return e
		}
		h, first, e := auditInitial(owner, kind, day)
		if e != nil {
			return e
		}
		s.log, e = store.CompleteControlCreation(path, h, first, auditValueValidator(owner, kind, day))
		if e != nil {
			return e
		}
		s.path = path
	}
	return nil
}

// inspectAudit は通常checkでは無変更、起動時は不完全末尾のみ後のimport復旧へ残す。
// 未完了の作成は正規の所有者・日付・fileだけ許し、実際の復旧時に全prefix一致を要求する。
func inspectAudit(cfg Config, state store.ControlState, minimum uint32, allowPending bool) error {
	root := filepath.Join(cfg.DataDir, "audit")
	if e := privatePath(root, true); e != nil {
		return e
	}
	owners, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	if len(owners) == 0 {
		return nil
	}
	if minimum < 9 {
		return store.ErrCorrupt
	}
	dirs, e := siteDirectories(state)
	if e != nil {
		return e
	}
	site := siteID(state)
	for _, ownerDir := range owners {
		var owner domain.ID
		raw, _ := json.Marshal(ownerDir.Name())
		if e = json.Unmarshal(raw, &owner); e != nil {
			return e
		}
		kind := "board"
		if owner == site {
			kind = "site"
		} else if dirs[owner] == nil {
			return store.ErrCorrupt
		}
		path := filepath.Join(root, ownerDir.Name())
		if e = privatePath(path, true); e != nil {
			return e
		}
		days, e := os.ReadDir(path)
		if e != nil {
			return e
		}
		seen := map[domain.ID]bool{}
		for _, day := range days {
			h, _, e := auditInitial(owner, kind, day.Name())
			if e != nil {
				return e
			}
			if e = inspectAuditDay(filepath.Join(path, day.Name()), h, kind, day.Name(), allowPending, seen, minimum); e != nil {
				return e
			}
		}
	}
	return nil
}
func inspectAuditDay(path string, h store.Header, kind, day string, allowPending bool, seen map[domain.ID]bool, minimum uint32) error {
	if e := privatePath(path, true); e != nil {
		return e
	}
	files, e := os.ReadDir(path)
	if e != nil {
		return e
	}
	current := false
	for _, file := range files {
		if file.Name() != "control.current" && file.Name() != "control-000001.wal" {
			return store.ErrCorrupt
		}
		if e = privatePath(filepath.Join(path, file.Name()), false); e != nil {
			return e
		}
		current = current || file.Name() == "control.current"
	}
	if e = inspectAuditInitialPrefix(path, h.Owner, kind, day, current); e != nil {
		return e
	}
	if !current {
		if allowPending {
			return nil
		}
		return store.ErrIncomplete
	}
	state, e := store.InspectControl(path, 4, h.Owner, h.Key, auditValueValidator(h.Owner, kind, day))
	if allowPending && errors.Is(e, store.ErrIncomplete) {
		return nil
	}
	if e != nil {
		return e
	}
	if _, ok := state.Rows["import_receipt:origin"]; !ok {
		return store.ErrCorrupt
	}
	if _, ok := state.Rows["import_receipt:source"]; ok && minimum < 10 {
		return store.ErrCorrupt
	}
	for key, row := range state.Rows {
		if strings.HasPrefix(key, "audit_entry:") {
			id, expires, e := auditStoredIdentity(row.Value)
			if e != nil {
				return e
			}
			if isThreadAudit(row.Value) && minimum < 28 {
				return store.ErrCorrupt
			}
			if seen[id] {
				return store.ErrCorrupt
			}
			seen[id] = true
			if row.Expires == nil || *row.Expires != expires {
				return store.ErrCorrupt
			}
		} else if strings.HasPrefix(key, "import_receipt:thread:") && minimum < 28 {
			return store.ErrCorrupt
		} else if row.Expires != nil {
			return store.ErrCorrupt
		}
	}
	return nil
}

// inspectAuditInitialPrefix は作成途中にも正規の初期byte列だけを許し、破損の上書きを防ぐ。
func inspectAuditInitialPrefix(path string, owner domain.ID, kind, day string, current bool) error {
	h, frame, e := auditInitial(owner, kind, day)
	if e != nil {
		return e
	}
	header, e := store.EncodeHeader(h)
	if e != nil {
		return e
	}
	want := append(header, frame...)
	f, e := os.Open(filepath.Join(path, "control-000001.wal"))
	if os.IsNotExist(e) && !current {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	got := make([]byte, len(want))
	n, e := io.ReadFull(f, got)
	if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
		return e
	}
	if !bytes.Equal(got[:n], want[:n]) || current && n != len(want) {
		return store.ErrCorrupt
	}
	if !current {
		info, e := f.Stat()
		if e != nil {
			return e
		}
		if info.Size() > int64(len(want)) {
			return store.ErrCorrupt
		}
	}
	return nil
}
