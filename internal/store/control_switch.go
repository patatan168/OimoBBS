// 制御snapshotと空deltaを同期してからcurrentを置換し、追記先を交換する。
package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"

	"oimobbs/internal/domain"
)

// SwitchSnapshot は所有ワーカーから、現在の全状態を持つ次世代snapshotを設置する。
// validatorがsnapshotの値も検証できる所有単位に限定する。監査移管の認可は呼出元の責務。
// 旧世代は削除しない。保存開始後の失敗はUnknownとなり、このlogへの追記と再切替を禁止する。
func (c *ControlLog) SwitchSnapshot(raw []byte) CommitResult {
	return c.switchSnapshot(raw, func(string) error { return nil })
}

// ResumeSnapshot は永続intentと排他を持つ停止中の呼出元専用。既存の一致prefixだけを補完する。
// 候補の認証・元状態/監査との照合・作業中の通常起動禁止は呼出元の責務。
func (c *ControlLog) ResumeSnapshot(raw []byte) CommitResult {
	return c.switchSnapshotMode(raw, func(string) error { return nil }, true)
}

// switchSnapshot の境界hookは永続化途中の失敗・中断を試験するために使う。
func (c *ControlLog) switchSnapshot(raw []byte, boundary func(string) error) CommitResult {
	return c.switchSnapshotMode(raw, boundary, false)
}
func (c *ControlLog) switchSnapshotMode(raw []byte, boundary func(string) error, resume bool) (result CommitResult) {
	if c.writer.stopped {
		return CommitResult{Unknown, errors.New("writer stopped")}
	}
	if c.header.Generation == math.MaxUint64 {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	h := c.header
	h.Generation++
	h.BaseSeq = uint64(c.state.Seq)
	validate := c.snapshotValidator
	if validate == nil {
		validate = c.validator
	}
	state, err := DecodeControlSnapshot(raw, h, validate)
	if err != nil {
		return CommitResult{NotWritten, err}
	}
	if !reflect.DeepEqual(state, c.state) {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	dir := filepath.Dir(c.file.Name())
	if err = privateRegular(dir, true); err != nil {
		return CommitResult{NotWritten, err}
	}
	snapName := fmt.Sprintf("control-%06d.snap", h.Generation)
	deltaName := fmt.Sprintf("control-%06d.wal", h.Generation)
	// 既存の中断候補を上書きしない。所有ワーカーとプロセス排他を前提とする。
	for _, name := range []string{snapName, deltaName} {
		if resume {
			continue
		}
		if _, err = os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = os.ErrExist
			}
			return CommitResult{NotWritten, err}
		}
	}
	hb, err := EncodeHeader(h)
	if err != nil {
		return CommitResult{NotWritten, err}
	}
	m := ControlManifest{Schema: 1, Kind: h.Kind, Owner: h.Owner, Subkey: domain.U64(h.Key), Generation: domain.U64(h.Generation), Snapshot: &ControlSnapshot{File: snapName, Length: domain.U64(len(raw)), SHA: sha256.Sum256(raw), Seq: c.state.Seq}, Delta: Delta{File: deltaName, BaseSeq: c.state.Seq, RequiredSeq: c.state.Seq, RequiredEnd: 64, RequiredSHA: sha256.Sum256(hb)}}
	current, err := encodeControlCurrent(m)
	if err != nil {
		return CommitResult{NotWritten, err}
	}
	// 以降のエラーでは結果を推測して継続せず、再起動によるcurrentの再判定を要求する。
	result.Status = Unknown
	defer func() {
		if result.Status != Durable {
			c.writer.stopped = true
		}
	}()
	writeFile := writeSwitchFile
	if resume {
		writeFile = completePrefix
	}
	if err = writeFile(filepath.Join(dir, snapName), raw); err != nil {
		return CommitResult{Unknown, err}
	}
	if err = boundary("snapshot_sync"); err != nil {
		return CommitResult{Unknown, err}
	}
	// 保存byteを読み直し、保存時に検証した状態との一致を確認する。
	saved, err := readBounded(filepath.Join(dir, snapName), maxControlSnapshot)
	if err != nil {
		return CommitResult{Unknown, err}
	}
	if !bytes.Equal(saved, raw) {
		return CommitResult{Unknown, ErrCorrupt}
	}
	if err = writeFile(filepath.Join(dir, deltaName), hb); err != nil {
		return CommitResult{Unknown, err}
	}
	if err = SyncDirectory(dir); err != nil {
		return CommitResult{Unknown, err}
	}
	if err = boundary("generation_sync"); err != nil {
		return CommitResult{Unknown, err}
	}
	next, err := os.OpenFile(filepath.Join(dir, deltaName), os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return CommitResult{Unknown, err}
	}
	adopted := false
	defer func() {
		if !adopted {
			result.Err = errors.Join(result.Err, next.Close())
		}
	}()
	if err = installControlSwitch(dir, current, boundary); err != nil {
		return CommitResult{Unknown, err}
	}
	if err = c.file.Close(); err != nil {
		return CommitResult{Unknown, err}
	}
	c.file, c.header, c.writer = next, h, NewWriter(next)
	c.snapshot = m.Snapshot
	adopted = true
	return CommitResult{Durable, nil}
}

// writeSwitchFile は既存ファイルを上書きせず、内容を同期して閉じる。
func writeSwitchFile(path string, raw []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if err = writeFull(f, raw); err != nil {
		return err
	}
	return f.Sync()
}

// installControlSwitch はrename前後の境界を明示し、directory Sync後だけ成功する。
func installControlSwitch(dir string, raw []byte, boundary func(string) error) error {
	return installNamedSwitch(dir, "control.current", raw, boundary)
}

// installNamedSwitch は同期済みcurrentをrenameし、親ディレクトリの同期まで完了する。
func installNamedSwitch(dir, name string, raw []byte, boundary func(string) error) (err error) {
	f, err := os.CreateTemp(dir, ".install-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = writeFull(f, raw)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = boundary("current_sync"); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	if err = boundary("current_rename"); err != nil {
		return err
	}
	if err = SyncDirectory(dir); err != nil {
		return err
	}
	return boundary("current_directory_sync")
}
