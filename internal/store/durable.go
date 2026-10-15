// 書込開始後の不明な結果を隔離し、Sync前の成功を禁止する。
package store

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// MaxCommitFramesは一括同期の件数上限。総bytesの8MiB上限も別途適用する。
const MaxCommitFrames = 64

type CommitStatus uint8

const (
	NotWritten CommitStatus = iota
	Durable
	Unknown
)

type CommitResult struct {
	Status CommitStatus
	Err    error
}

// SyncWriter は障害注入可能な書込・同期境界。
type SyncWriter interface {
	Write([]byte) (int, error)
	Sync() error
}

// Writer は所有ワーカーの直列コミットを補助する。不明結果の後には再開しない。
type Writer struct {
	mu      sync.Mutex
	file    SyncWriter
	stopped bool
	stats   CommitStats
}

// CommitStats はこのwriterのWAL書込/同期の実呼出し数。親ディレクトリ同期は含まない。
// 再起動で零へ戻り、本文や接続情報を含まない。
type CommitStats struct {
	Writes uint64
	Syncs  uint64
	Bytes  uint64
}

// Stats は保存境界の呼出し数をmutexで確定して返す。ディスク物理I/Oとは区別する。
func (w *Writer) Stats() CommitStats { w.mu.Lock(); defer w.mu.Unlock(); return w.stats }

func NewWriter(file SyncWriter) *Writer { return &Writer{file: file} }

// Commit は完成フレームを一度書き、Sync完了後だけDurableを返す。
func (w *Writer) Commit(prepared []byte) CommitResult {
	return w.commitFrames([][]byte{prepared})
}

// CommitBatchは既存形式の最大64frameを一度のWrite/Syncで保存する。
// 不完全なframeは書込前に拒否し、書込開始後の失敗では停止する。
func (w *Writer) CommitBatch(frames [][]byte) CommitResult {
	return w.commitFrames(frames)
}

func (w *Writer) commitFrames(frames [][]byte) CommitResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return CommitResult{Unknown, errors.New("writer stopped")}
	}
	if len(frames) == 0 || len(frames) > MaxCommitFrames {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	var size int
	for _, prepared := range frames {
		_, n, e := ReadFrame(bytes.NewReader(prepared))
		if e != nil || n != int64(len(prepared)) {
			return CommitResult{NotWritten, ErrCorrupt}
		}
		size += len(prepared)
		if len(frames) > 1 && size > 8<<20 {
			return CommitResult{NotWritten, ErrCorrupt}
		}
	}
	prepared := frames[0]
	if len(frames) > 1 {
		prepared = make([]byte, 0, size)
		for _, frame := range frames {
			prepared = append(prepared, frame...)
		}
	}
	w.stats.Writes++
	nWritten, e := w.file.Write(prepared)
	if nWritten > 0 {
		w.stats.Bytes += uint64(nWritten)
	}
	if e == nil && nWritten != len(prepared) {
		e = io.ErrShortWrite
	}
	if e == nil {
		w.stats.Syncs++
		e = w.file.Sync()
	}
	if e != nil {
		w.stopped = true
		return CommitResult{Unknown, e}
	}
	return CommitResult{Durable, nil}
}

// InstallCurrent は同じディレクトリ内の一時fileをSyncし、renameと親Syncを行う。
// renameを試みた後の失敗は呼出元でwriterを停止する必要がある。
func InstallCurrent(dir string, b []byte) error {
	if _, e := DecodeCurrent(b); e != nil {
		return e
	}
	return atomicFile(dir, "current.json", b)
}
func atomicFile(dir, name string, b []byte) (err error) {
	f, e := os.CreateTemp(dir, ".install-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	return SyncDirectory(dir)
}

// SyncDirectory はfile名の作成・置換を永続化する。
func SyncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	e = f.Sync()
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
