// 制御journalのcurrentとWALを実fileへ保存・復旧する。
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"sync/atomic"
)

type ControlSnapshot struct {
	File   string      `json:"file"`
	Length domain.U64  `json:"length"`
	SHA    domain.Hash `json:"sha256"`
	Seq    domain.U64  `json:"seq"`
}
type ControlManifest struct {
	Schema     uint32           `json:"schema"`
	Kind       uint16           `json:"kind"`
	Owner      domain.ID        `json:"owner_id"`
	Subkey     domain.U64       `json:"subkey"`
	Generation domain.U64       `json:"generation"`
	Snapshot   *ControlSnapshot `json:"snapshot"`
	Delta      Delta            `json:"delta"`
}

func (m ControlManifest) validate() error {
	if m.Schema != 1 || m.Kind < 1 || m.Kind > 9 || m.Owner == (domain.ID{}) || m.Generation == 0 || m.Delta.File != fmt.Sprintf("control-%06d.wal", m.Generation) || m.Delta.RequiredEnd < 64 {
		return ErrCorrupt
	}
	if m.Snapshot == nil {
		if m.Delta.BaseSeq != 0 || m.Delta.RequiredSeq == 0 || m.Delta.RequiredEnd <= 64 {
			return ErrCorrupt
		}
	} else {
		p := m.Snapshot
		if p.File != fmt.Sprintf("control-%06d.snap", m.Generation) || p.Seq != m.Delta.BaseSeq || p.Length < 64 || m.Delta.RequiredSeq < p.Seq || (m.Delta.RequiredSeq == p.Seq) != (m.Delta.RequiredEnd == 64) {
			return ErrCorrupt
		}
	}
	return nil
}
func encodeControlCurrent(m ControlManifest) ([]byte, error) {
	if e := m.validate(); e != nil {
		return nil, e
	}
	b, e := json.Marshal(m)
	if e != nil {
		return nil, e
	}
	return json.Marshal(currentEnvelope{Manifest: b, SHA: sha256.Sum256(b)})
}
func decodeControlCurrent(b []byte) (ControlManifest, error) {
	var m ControlManifest
	if len(b) > 16<<10 {
		return m, ErrCorrupt
	}
	var env currentEnvelope
	if e := strictjson.Decode(b, &env); e != nil {
		return m, e
	}
	if sha256.Sum256(env.Manifest) != env.SHA {
		return m, ErrCorrupt
	}
	if e := strictjson.Decode(env.Manifest, &m); e != nil {
		return m, e
	}
	return m, m.validate()
}

// EncodeControlCurrent は復旧候補照合用に既存current形式の正確なbytesを返す。保存は行わない。
func EncodeControlCurrent(m ControlManifest) ([]byte, error) { return encodeControlCurrent(m) }

// ControlLog は一所有単位の制御正本。所有ワーカーだけから呼ぶ。
type ControlLog struct {
	backupPinned      backupPinFlag
	file              *os.File
	writer            *Writer
	header            Header
	state             ControlState
	stateExposed      atomic.Bool
	validator         ValueValidator
	snapshotValidator ValueValidator
	snapshot          *ControlSnapshot
}

// CreateControl は初期操作をSyncし、その必須確定位置をcontrol.currentへ保存する。
func CreateControl(dir string, h Header, prepared []byte, validate ValueValidator) (*ControlLog, error) {
	if h.Kind == 0 || h.BaseSeq != 0 || h.Generation != 1 {
		return nil, ErrCorrupt
	}
	hb, e := EncodeHeader(h)
	if e != nil {
		return nil, e
	}
	f, n, e := ReadFrame(bytes.NewReader(prepared))
	if e != nil || n != int64(len(prepared)) {
		return nil, ErrCorrupt
	}
	state, e := ApplyControl(ControlState{}, h.Kind, f, validate)
	if e != nil {
		return nil, e
	}
	if e = privateRegular(filepath.Dir(dir), true); e != nil {
		return nil, e
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return nil, e
	}
	if e = SyncDirectory(filepath.Dir(dir)); e != nil {
		return nil, e
	}
	name := "control-000001.wal"
	file, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	if e = writeFull(file, hb); e != nil {
		return nil, e
	}
	writer := NewWriter(file)
	if r := writer.Commit(prepared); r.Status != Durable {
		return nil, r.Err
	}
	if e = SyncDirectory(dir); e != nil {
		return nil, e
	}
	stored, e := EncodeWALBlock([][]byte{prepared})
	if e != nil {
		return nil, e
	}
	raw := append(hb, stored...)
	m := ControlManifest{Schema: 1, Kind: h.Kind, Owner: h.Owner, Subkey: domain.U64(h.Key), Generation: 1, Delta: Delta{File: name, RequiredSeq: 1, RequiredEnd: domain.U64(len(raw)), RequiredSHA: sha256.Sum256(raw)}}
	b, e := encodeControlCurrent(m)
	if e != nil {
		return nil, e
	}
	if e = atomicFile(dir, "control.current", b); e != nil {
		return nil, e
	}
	ok = true
	return &ControlLog{file: file, writer: writer, header: h, state: state, validator: validate}, nil
}

// OpenControl は所有先・CRC・必須位置・全mutationを検査してから更新を許可する。
func OpenControl(dir string, kind uint16, owner domain.ID, subkey uint64, validate ValueValidator) (*ControlLog, error) {
	return openControl(dir, kind, owner, subkey, validate, validate, true)
}

// InspectControl はWALを読取り専用で検査する。不完全末尾を切り詰めずErrIncompleteを返す。
func InspectControl(dir string, kind uint16, owner domain.ID, subkey uint64, validate ValueValidator) (ControlState, error) {
	log, err := openControl(dir, kind, owner, subkey, validate, validate, false)
	if err != nil {
		return ControlState{}, err
	}
	state := log.State()
	if err = log.Close(); err != nil {
		return ControlState{}, err
	}
	return state, nil
}

// OpenControlWithValidators はsnapshotの現在値とWALの状態遷移を別々に検証する。
// 必須行や所有者間の整合性は呼出元で追加検査する。どちらの検証器も省略できない。
func OpenControlWithValidators(dir string, kind uint16, owner domain.ID, subkey uint64, mutation, snapshot ValueValidator) (*ControlLog, error) {
	if mutation == nil || snapshot == nil {
		return nil, ErrCorrupt
	}
	return openControl(dir, kind, owner, subkey, mutation, snapshot, true)
}

// InspectControlWithValidators は独立した状態検証器でsnapshotを読取り専用検査する。
func InspectControlWithValidators(dir string, kind uint16, owner domain.ID, subkey uint64, mutation, snapshot ValueValidator) (ControlState, error) {
	if mutation == nil || snapshot == nil {
		return ControlState{}, ErrCorrupt
	}
	log, err := openControl(dir, kind, owner, subkey, mutation, snapshot, false)
	if err != nil {
		return ControlState{}, err
	}
	state := log.State()
	if err = log.Close(); err != nil {
		return ControlState{}, err
	}
	return state, nil
}

func openControl(dir string, kind uint16, owner domain.ID, subkey uint64, validate, snapshotValidate ValueValidator, repair bool) (*ControlLog, error) {
	for _, p := range []string{dir, filepath.Join(dir, "control.current")} {
		if e := privateRegular(p, p == dir); e != nil {
			return nil, e
		}
	}
	b, e := readBounded(filepath.Join(dir, "control.current"), 16<<10)
	if e != nil {
		return nil, e
	}
	m, e := decodeControlCurrent(b)
	if e != nil || m.Kind != kind || m.Owner != owner || uint64(m.Subkey) != subkey {
		return nil, ErrCorrupt
	}
	state := ControlState{}
	if m.Snapshot != nil {
		state, e = readControlSnapshot(dir, m, snapshotValidate, repair)
		if e != nil {
			return nil, e
		}
	}
	path := filepath.Join(dir, m.Delta.File)
	if e = privateRegular(path, false); e != nil {
		return nil, e
	}
	mode := os.O_RDONLY
	if repair {
		mode = os.O_RDWR
	}
	file, e := os.OpenFile(path, mode, 0)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	h := Header{Kind: kind, Owner: owner, Key: subkey, BaseSeq: uint64(m.Delta.BaseSeq), Generation: uint64(m.Generation)}
	end, partial, e := Scan(file, h, m.Delta, func(f Frame) error {
		next, e := applyControlReplay(state, kind, f, validate)
		if e == nil {
			state = next
		}
		return e
	})
	if e != nil {
		return nil, e
	}
	if partial {
		if !repair {
			return nil, ErrIncomplete
		}
		if e = file.Truncate(end); e != nil {
			return nil, e
		}
	}
	// 完全な末尾でも前processのSync完了は分からない。復旧後の別WAL更新より先に確定する。
	// InspectControlの読取り専用検査では同期・修復とも行わない。
	if repair {
		if e = file.Sync(); e != nil {
			return nil, e
		}
		if e = SyncDirectory(dir); e != nil {
			return nil, e
		}
		if e = SyncDirectory(filepath.Dir(dir)); e != nil {
			return nil, e
		}
	}
	if _, e = file.Seek(end, io.SeekStart); e != nil {
		return nil, e
	}
	ok = true
	return &ControlLog{file: file, writer: NewWriter(file), header: h, state: state, validator: validate, snapshotValidator: snapshotValidate, snapshot: m.Snapshot}, nil
}

// Append は対象行を検証し、Sync後だけ所有状態へ反映する。
// Stateで外へ渡したmapは一度複製し、その後の追記で旧参照を変更しない。
func (c *ControlLog) Append(prepared []byte) CommitResult {
	f, e := decodeFrameView(prepared)
	if e != nil || len(f.Records) != 1 {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	op, e := decodeControlOperation(f)
	if e != nil {
		return CommitResult{NotWritten, e}
	}
	if len(op.Mutations) < 1 || len(op.Mutations) > 256 {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	next, e := applyControlOperation(controlReplaySubset(c.state, op.Mutations), c.header.Kind, f.FirstSeq, op, c.validator, false)
	if e != nil {
		return CommitResult{NotWritten, e}
	}
	result := c.writer.Commit(prepared)
	if result.Status == Durable {
		old := c.state
		if c.stateExposed.Load() {
			old.Rows = make(map[string]ControlRow, len(c.state.Rows)+len(op.Mutations))
			for key, row := range c.state.Rows {
				old.Rows[key] = row
			}
		}
		c.state = mergeControlReplay(old, next, op.Mutations)
		c.stateExposed.Store(false)
	}
	return result
}

// AppendBatchは連続した既存frameの対象行を全件検証し、一度のSync後だけ反映する。
// 外へ渡したmapは成功時に複製し、取得済みStateは成功・失敗とも変化しない。
func (c *ControlLog) AppendBatch(frames [][]byte) CommitResult {
	return c.AppendBatchChecked(frames, nil)
}

// AppendBatchChecked は全候補の検証と実保存bytesの確認後、一度のSyncで現在状態を更新する。
func (c *ControlLog) AppendBatchChecked(frames [][]byte, before func(int64) error) CommitResult {
	return c.appendFramesChecked(frames, before, MaxCommitFrames)
}

// AppendSeriesChecked は非必須kind8 journalの最大四blockを全件検査し、一度のSyncで確定する。
// 投稿などの通常一括追記は64frame上限のまま。列全体の8MiB制限を変更しない。
func (c *ControlLog) AppendSeriesChecked(frames [][]byte, before func(int64) error) CommitResult {
	if c.header.Kind != 8 {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	return c.appendFramesChecked(frames, before, MaxCommitSeriesFrames)
}

func (c *ControlLog) appendFramesChecked(frames [][]byte, before func(int64) error, limit int) CommitResult {
	if len(frames) == 0 || len(frames) > limit {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	var totalBytes int
	for _, prepared := range frames {
		// Writerと同じ上限を、全frameの候補を保持する前にも適用する。
		if len(frames) > 1 && len(prepared) > (8<<20)-totalBytes {
			return CommitResult{NotWritten, ErrCorrupt}
		}
		totalBytes += len(prepared)
	}
	decoded := decodeControlFrames(frames, totalBytes)
	var mutations []Mutation
	for _, prepared := range decoded {
		if prepared.err != nil {
			return CommitResult{NotWritten, prepared.err}
		}
		mutations = append(mutations, prepared.op.Mutations...)
	}
	// 後続frameが同じ行を参照・削除する場合も、同じ候補内で順番通り検査する。
	next := controlReplaySubset(c.state, mutations)
	for _, prepared := range decoded {
		var e error
		next, e = applyControlOperation(next, c.header.Kind, prepared.firstSeq, prepared.op, c.validator, false)
		if e != nil {
			return CommitResult{NotWritten, e}
		}
	}
	var result CommitResult
	if limit == MaxCommitFrames {
		result = c.writer.CommitBatchChecked(frames, before)
	} else {
		result = c.writer.CommitSeriesChecked(frames, before)
	}
	if result.Status == Durable {
		old := c.state
		if c.stateExposed.Load() {
			old.Rows = make(map[string]ControlRow, len(c.state.Rows)+len(mutations))
			for key, row := range c.state.Rows {
				old.Rows[key] = row
			}
		}
		c.state = mergeControlReplay(old, next, mutations)
		c.stateExposed.Store(false)
	}
	return result
}

// State は所有ワーカー向けの不変な復旧状態。値とmapの変更は禁止。
func (c *ControlLog) State() ControlState {
	c.stateExposed.Store(true)
	return c.state
}
func (c *ControlLog) Close() error { return c.file.Close() }

// CommitStats はこの制御WALの保存呼出し数を返す。current/親同期は含まない。
func (c *ControlLog) CommitStats() CommitStats { return c.writer.Stats() }

// SnapshotIdentity は復旧済みsnapshotの参照を値で返す。内容や秘密の値は含まない。
func (c *ControlLog) SnapshotIdentity() (ControlSnapshot, bool) {
	if c.snapshot == nil {
		return ControlSnapshot{}, false
	}
	return *c.snapshot, true
}

// InspectControlManifest はcurrentの権限・完全型・SHAを読み取り専用で検査する。
// 参照先のsnapshot/WAL内容の検証はOpenControl/InspectControlで別途行う。
func InspectControlManifest(dir string) (ControlManifest, error) {
	if err := privateRegular(dir, true); err != nil {
		return ControlManifest{}, err
	}
	path := filepath.Join(dir, "control.current")
	if err := privateRegular(path, false); err != nil {
		return ControlManifest{}, err
	}
	raw, err := readBounded(path, 16<<10)
	if err != nil {
		return ControlManifest{}, err
	}
	return decodeControlCurrent(raw)
}
