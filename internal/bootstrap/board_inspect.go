// サイトdirectory、作成job、板controlの三者を照合してから公開用一覧を構築する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/platform"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const maxPersistentBoards = 128

// BoardInfo は管理一覧で使用する、秘密と投稿を含まない板情報。
type BoardInfo struct {
	ID       domain.ID  `json:"id"`
	Key      string     `json:"key"`
	Name     string     `json:"name"`
	Status   string     `json:"status"`
	Revision domain.U64 `json:"revision"`
}
type persistedBoard struct {
	info      BoardInfo
	directory *boardDirectory
	job       provisionJob
	control   store.ControlState
}

func inspectBoards(cfg Config, site store.ControlState, allowPending bool) ([]persistedBoard, error) {
	return inspectBoardsMode(cfg, site, allowPending, false)
}
func inspectBoardsMode(cfg Config, site store.ControlState, allowPending, allowPosting bool) ([]persistedBoard, error) {
	dirs, err := siteDirectories(site)
	if err != nil {
		return nil, err
	}
	jobIDs, err := childIDs(filepath.Join(cfg.DataDir, "jobs"))
	if err != nil {
		return nil, err
	}
	diskBoards, err := childIDs(filepath.Join(cfg.DataDir, "boards"))
	if err != nil {
		return nil, err
	}
	master, err := readPrivate(filepath.Join(cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return nil, err
	}
	out := make([]persistedBoard, 0, len(jobIDs))
	seenBoards := map[domain.ID]bool{}
	seenKeys := map[string]bool{}
	for _, jobID := range jobIDs {
		job, err := inspectJob(cfg.DataDir, jobID)
		if err != nil {
			return nil, err
		}
		if job.OwnerAdmin != nil {
			var siteValue siteState
			if err = strictjson.Decode(site.Rows["site:state"].Value, &siteValue); err != nil {
				return nil, err
			}
			if siteValue.MinimumReader < 63 {
				return nil, errors.New("online board creation requires reader63")
			}
			if job.Parameters.Settings.Posting.Create == "cap_only" && siteValue.MinimumReader < 73 {
				return nil, errors.New("CAP-only board creation requires reader73")
			}
		}
		id := job.Parameters.BoardID
		if id == siteID(site) || seenBoards[id] || seenKeys[job.Parameters.Key] || job.Request != boardRequest(secret, job.Parameters.Key, job.Parameters.Name, job.Parameters.Settings.Posting.Create) {
			return nil, errors.New("duplicate or inconsistent board job")
		}
		seenBoards[id] = true
		seenKeys[job.Parameters.Key] = true
		entry := persistedBoard{job: job, directory: dirs[id], info: BoardInfo{ID: id, Key: job.Parameters.Key, Name: job.Parameters.Name, Status: "provisioning"}}
		if err = inspectBoard(cfg, &entry, allowPending, allowPosting); err != nil {
			return nil, fmt.Errorf("board %s: %w", id.String(), err)
		}
		if row, ok := entry.control.Rows["board:state"]; ok {
			var board boardValue
			var siteValue siteState
			if err := strictjson.Decode(row.Value, &board); err != nil {
				return nil, err
			}
			if err := strictjson.Decode(site.Rows["site:state"].Value, &siteValue); err != nil {
				return nil, err
			}
			m, err := store.InspectControlManifest(controlOwnerPath(cfg.DataDir, "board", entry.info.ID))
			if err != nil {
				return nil, err
			}
			if m.Snapshot != nil && siteValue.MinimumReader < 12 {
				return nil, errors.New("board snapshot requires reader version 12")
			}
			for k := range entry.control.Rows {
				if strings.HasPrefix(k, "cap_command:") && siteValue.MinimumReader < capCommandsReader {
					return nil, errors.New("CAP command requires reader 79")
				}
				if strings.HasPrefix(k, "post_evidence_query:") && siteValue.MinimumReader < 64 {
					return nil, errors.New("post evidence audit requires reader 64")
				}
				if strings.HasPrefix(k, "carry_retirement:") && siteValue.MinimumReader < bodyCarryRetirementReader {
					return nil, errors.New("carry retirement requires reader 58")
				}
				if strings.HasPrefix(k, "evidence_checkpoint:") && siteValue.MinimumReader < 55 {
					return nil, errors.New("required checkpoint requires reader 55")
				}
				if (strings.HasPrefix(k, "local_rules:") || strings.HasPrefix(k, "local_rules_receipt:")) && siteValue.MinimumReader < 72 {
					return nil, errors.New("local rules require reader 72")
				}
				if (strings.HasPrefix(k, "thread_settings:") || strings.HasPrefix(k, "thread_settings_receipt:")) && siteValue.MinimumReader < 11 {
					return nil, errors.New("thread settings require reader version 11")
				}
				if strings.HasPrefix(k, "board_rule:") && siteValue.MinimumReader < capCommandsReader {
					var rule denialRule
					if err := strictjson.Decode(entry.control.Rows[k].Value, &rule); err != nil {
						return nil, err
					}
					if rule.Expires != permanentDenyExpiry && rule.Expires-rule.Starts > domain.Time(maxDenyMinutes)*60e9 {
						return nil, errors.New("long token ban requires reader 79")
					}
				}
				if strings.HasPrefix(k, "board_rule:") && siteValue.MinimumReader < 8 {
					return nil, errors.New("denial rules require reader version 8")
				}
			}
			if err := validateAnonymousBoardFeatures(site, entry.control); err != nil {
				return nil, err
			}
			if e := validateIdentityReader(siteValue, board); e != nil {
				return nil, e
			}
			if board.Settings.Version > 1 && siteValue.MinimumReader < 7 {
				return nil, errors.New("board settings require reader version 7")
			}
		}
		out = append(out, entry)
	}
	for id := range dirs {
		if !seenBoards[id] {
			return nil, errors.New("board directory has no provisioning record")
		}
	}
	for _, id := range diskBoards {
		if !seenBoards[id] {
			return nil, errors.New("orphan board directory")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].info.Key < out[j].info.Key })
	return out, nil
}
func siteID(state store.ControlState) domain.ID {
	var v siteState
	_ = json.Unmarshal(state.Rows["site:state"].Value, &v)
	return v.ID
}
func siteDirectories(state store.ControlState) (map[domain.ID]*boardDirectory, error) {
	var site siteState
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return nil, err
	}
	categories := map[domain.ID]bool{}
	for _, c := range site.Categories {
		categories[c.ID] = true
	}
	if len(categories) > 0 && site.MinimumReader < 77 {
		return nil, store.ErrCorrupt
	}
	dirs := map[domain.ID]*boardDirectory{}
	keys := map[string]bool{}
	for key, row := range state.Rows {
		if !strings.HasPrefix(key, "board_directory:") {
			continue
		}
		var id domain.ID
		if err := json.Unmarshal([]byte(`"`+strings.TrimPrefix(key, "board_directory:")+`"`), &id); err != nil {
			return nil, err
		}
		var v boardDirectory
		if err := strictjson.Decode(row.Value, &v); err != nil {
			return nil, err
		}
		if v.CategoryID != nil && (!categories[*v.CategoryID] || site.MinimumReader < 77) {
			return nil, store.ErrCorrupt
		}
		if keys[v.Key] || id == siteID(state) {
			return nil, errors.New("duplicate board key or owner")
		}
		keys[v.Key] = true
		dirs[id] = &v
	}
	if len(dirs) > maxPersistentBoards {
		return nil, errors.New("board limit exceeded")
	}
	return dirs, nil
}
func childIDs(dir string) ([]domain.ID, error) {
	if err := privatePath(dir, true); err != nil {
		return nil, err
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(maxPersistentBoards + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(names) > maxPersistentBoards {
		return nil, errors.New("owner directory limit exceeded")
	}
	ids := make([]domain.ID, 0, len(names))
	for _, name := range names {
		var id domain.ID
		if err = json.Unmarshal([]byte(`"`+name+`"`), &id); err != nil {
			return nil, errors.New("noncanonical storage owner directory")
		}
		if err = privatePath(filepath.Join(dir, name), true); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
func inspectJob(root string, id domain.ID) (provisionJob, error) {
	var job provisionJob
	dir := filepath.Join(root, "jobs", id.String())
	if err := requireEntries(dir, []string{"control.current", "control-000001.wal"}); err != nil {
		return job, err
	}
	state, err := store.InspectControl(dir, 6, id, 0, validateProvisionJob)
	if err != nil {
		return job, err
	}
	row, ok := state.Rows["job:"+id.String()]
	if !ok || len(state.Rows) != 1 {
		return job, store.ErrCorrupt
	}
	if err = strictjson.Decode(row.Value, &job); err != nil {
		return job, err
	}
	if !reflect.DeepEqual(row.Expires, job.Expires) {
		return job, store.ErrCorrupt
	}
	return job, nil
}
func inspectBoard(cfg Config, entry *persistedBoard, allowPending, allowPosting bool) error {
	d, j := entry.directory, entry.job
	if d != nil && (d.JobID != j.ID || d.Key != j.Parameters.Key || d.CategoryID != nil && (d.Status != "active" || j.State != "completed")) {
		return errors.New("directory and job differ")
	}
	active := d != nil && d.Status == "active"
	if (!active || j.State != "completed") && !allowPending {
		return errors.New("board provisioning pending; use board recover")
	}
	if j.State == "completed" && !active {
		return errors.New("completed job has no active directory")
	}
	dir := filepath.Join(cfg.DataDir, "boards", j.Parameters.BoardID.String())
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		if active {
			return errors.New("active board missing")
		}
		return nil
	} else if err != nil {
		return err
	}
	if d == nil {
		return errors.New("board exists before site provisioning")
	}
	if err := privatePath(dir, true); err != nil {
		return err
	}
	if !active {
		return inspectPendingBoard(dir, j)
	}
	if err := requireEntries(dir, []string{"control", "threads"}); err != nil {
		return err
	}
	if allowPosting {
		if err := privatePath(filepath.Join(dir, "threads"), true); err != nil {
			return err
		}
	} else if err := requireEmpty(filepath.Join(dir, "threads")); err != nil {
		return err
	}
	state, err := inspectBoardControl(dir, j)
	if err != nil {
		return err
	}
	entry.control = state
	entry.info.Status = "open"
	entry.info.Revision = state.Rows["board:state"].Revision
	return nil
}
func inspectBoardControl(dir string, job provisionJob) (store.ControlState, error) {
	state, err := inspectRuntimeControl(filepath.Dir(filepath.Dir(dir)), "board", job.Parameters.BoardID)
	if err != nil {
		return state, err
	}
	return inspectBoardState(state, job)
}

// inspectBoardState は復旧経路によらず、必須行・作成job・receipt・所有者を照合する。
func inspectBoardState(state store.ControlState, job provisionJob) (store.ControlState, error) {
	var v boardValue
	if err := strictjson.Decode(state.Rows["board:state"].Value, &v); err != nil {
		return state, err
	}
	count := 0
	ruleRows := 0
	threadRows := 0
	checkpointRows, e := inspectBoardCheckpointRows(state, job.Parameters.BoardID)
	if e != nil {
		return state, e
	}
	carryRows, e := inspectBoardCarryRetirementRows(state, job.Parameters.BoardID)
	if e != nil {
		return state, e
	}
	policyRows := 0
	queryRows := 0
	for k, row := range state.Rows {
		if strings.HasPrefix(k, "cap_command:") {
			var receipt capCommandReceipt
			if row.Expires != nil || snapshotCapCommandReceipt(strings.TrimPrefix(k, "cap_command:"), row.Value) != nil || strictjson.Decode(row.Value, &receipt) != nil || receipt.Board != job.Parameters.BoardID {
				return state, store.ErrCorrupt
			}
			count++
		}
		if strings.HasPrefix(k, "post_evidence_query:") {
			if row.Expires != nil || validatePostEvidenceAudit(strings.TrimPrefix(k, "post_evidence_query:"), nil, row.Value) != nil {
				return state, store.ErrCorrupt
			}
			queryRows++
		}
		if strings.HasPrefix(k, "posting_policy:") {
			policyRows++
		}
		if strings.HasPrefix(k, "local_rules:") || strings.HasPrefix(k, "local_rules_receipt:") {
			active, ok := state.Rows["local_rules:active"]
			if !ok || row.Expires != nil {
				return state, store.ErrCorrupt
			}
			if strings.HasPrefix(k, "local_rules_receipt:") {
				var receipt localRulesReceipt
				if e := strictjson.Decode(row.Value, &receipt); e != nil {
					return state, e
				}
				if receipt.Result.Board != job.Parameters.BoardID || receipt.Result.Revision > active.Revision {
					return state, store.ErrCorrupt
				}
			}
			threadRows++
		}
		if strings.HasPrefix(k, "thread_settings:") || strings.HasPrefix(k, "thread_settings_receipt:") {
			active, ok := state.Rows["thread_settings:active"]
			if !ok || row.Expires != nil {
				return state, store.ErrCorrupt
			}
			if strings.HasPrefix(k, "thread_settings_receipt:") {
				var receipt threadSettingsReceipt
				if e := strictjson.Decode(row.Value, &receipt); e != nil {
					return state, e
				}
				if receipt.Result.Board != job.Parameters.BoardID || receipt.Result.Revision > active.Revision {
					return state, store.ErrCorrupt
				}
			}
			threadRows++
		}
		if strings.HasPrefix(k, "board_rule:") || strings.HasPrefix(k, "rule_receipt:") {
			if e := inspectRuleRow(k, row, job.Parameters.BoardID, state); e != nil {
				return state, e
			}
			ruleRows++
		}
		if strings.HasPrefix(k, "admin_receipt:") {
			var receipt adminBoardReceipt
			if e := strictjson.Decode(row.Value, &receipt); e != nil {
				return state, e
			}
			if receipt.Result.ID != job.Parameters.BoardID || receipt.Result.Key != job.Parameters.Key || receipt.Result.Name != job.Parameters.Name || receipt.Result.Revision > state.Rows["board:state"].Revision || row.Expires != nil {
				return state, store.ErrCorrupt
			}
			count++
		}
	}
	// 編集設定は制御WAL/snapshotが正本。24時間で満了する再送receiptの存続を要求しない。
	if len(state.Rows) != 3+count+ruleRows+threadRows+policyRows+checkpointRows+carryRows+queryRows || v.Name != job.Parameters.Name || v.Settings.Version == 1 && !reflect.DeepEqual(v.Settings, job.Parameters.Settings) {
		return state, store.ErrCorrupt
	}
	for _, key := range []string{"board:state", "key_watermark:thread", "bump_watermark:ranking"} {
		row, ok := state.Rows[key]
		if !ok || row.Expires != nil {
			return state, store.ErrCorrupt
		}
	}
	return state, nil
}

// inspectPendingBoard は初期frameの完全一致prefixだけを再開可能と判断する。
func inspectPendingBoard(dir string, job provisionJob) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "threads":
			if err = requireEmpty(filepath.Join(dir, "threads")); err != nil {
				return err
			}
		case "control":
		default:
			return errors.New("unknown provisioning entry")
		}
	}
	path := filepath.Join(dir, "control")
	if _, err = os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err = privatePath(path, true); err != nil {
		return err
	}
	if _, err = os.Lstat(filepath.Join(path, "control.current")); err == nil {
		state, err := inspectBoardControl(dir, job)
		if err != nil {
			return err
		}
		if state.Seq != 1 {
			return errors.New("inactive board was already modified")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	frame, err := boardInitialFrame(job)
	if err != nil {
		return err
	}
	header, err := store.EncodeHeader(store.Header{Kind: 2, Owner: job.Parameters.BoardID, Generation: 1})
	if err != nil {
		return err
	}
	expected := append(header, frame...)
	entries, err = os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "control-000001.wal" {
			return errors.New("unknown incomplete control file")
		}
	}
	b, err := readPrivate(filepath.Join(path, "control-000001.wal"), int64(len(expected)))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(b, expected[:len(b)]) {
		return errors.New("incomplete control differs from durable intent")
	}
	return nil
}

// ListBoards はサイトと板を読取り専用で照合する。作成途中のjobは再開せずエラーにする。
func ListBoards(cfg Config) (rows []BoardInfo, err error) {
	if err = cfg.validate(); err != nil {
		return nil, err
	}
	if err = cfg.checkTLS(time.Now()); err != nil {
		return nil, err
	}
	if err = privatePath(cfg.DataDir, true); err != nil {
		return nil, err
	}
	if err = privatePath(filepath.Join(cfg.DataDir, ".lock"), false); err != nil {
		return nil, err
	}
	lock, err := platform.Lock(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, platform.Unlock(lock)) }()
	report, err := checkLocked(cfg)
	if err != nil {
		return nil, err
	}
	state, err := inspectRuntimeControl(cfg.DataDir, "site", report.SiteID)
	if err != nil {
		return nil, err
	}
	entries, err := inspectBoards(cfg, state, false)
	if err != nil {
		return nil, err
	}
	rows = make([]BoardInfo, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, entry.info)
	}
	return rows, nil
}
