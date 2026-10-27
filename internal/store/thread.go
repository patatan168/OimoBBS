// スレッドWALとcurrentを使った実ファイル保存を実装する。
package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
)

// ThreadLog は板の所有列から使用する。公開状態の所有者ではない。
// 共有投稿batch中は列全体の待機下で、独立したWALごとに一つのgoroutineへ専有を委譲できる。
type ThreadLog struct {
	group        *ThreadCommitGroup
	backupPinned backupPinFlag
	file         *os.File
	writer       *Writer
	header       Header
	manifest     Manifest
	state        *domain.Thread
	dir          string
	end          int64
	records      []ThreadRecord
	dedupIndex   map[threadDedupKey][]int
	dedupIndexed int
	base         *PackSnapshot
	packLevel    uint8
	packCodec    uint8
}

// CreateThread は予約済みキーのcreateを保存する。既存ディレクトリへ上書きしない。
// 接続記録proposalのSync後に呼ぶ。成功だけでは公開・投稿成功の条件を満たさない。
func CreateThread(parent string, owner domain.ID, key uint64, prepared []byte) (*ThreadLog, error) {
	h := Header{Owner: owner, Key: key, Generation: 1}
	hb, e := EncodeHeader(h)
	if e != nil {
		return nil, e
	}
	if e = privateRegular(parent, true); e != nil {
		return nil, e
	}
	f, size, e := ReadFrame(bytes.NewReader(prepared))
	if e != nil || size != int64(len(prepared)) || f.FirstSeq != 1 || len(f.Records) != 1 {
		return nil, ErrCorrupt
	}
	candidate, e := applyFrame(nil, f)
	if e != nil {
		return nil, e
	}
	dir := filepath.Join(parent, fmt.Sprint(key))
	if e = os.Mkdir(dir, 0700); e != nil {
		return nil, e
	}
	if e = SyncDirectory(parent); e != nil {
		return nil, e
	}
	name := "delta-000001.wal"
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
	if result := writer.Commit(prepared); result.Status != Durable {
		return nil, result.Err
	}
	if e = SyncDirectory(dir); e != nil {
		return nil, e
	}
	stored, e := EncodeWALBlock([][]byte{prepared})
	if e != nil {
		return nil, e
	}
	raw := append(hb, stored...)
	m := Manifest{Schema: 1, BoardID: owner, ThreadKey: domain.U64(key), Generation: 1, Delta: Delta{File: name, RequiredSeq: 1, RequiredEnd: domain.U64(len(raw)), RequiredSHA: sha256.Sum256(raw)}}
	current, e := EncodeCurrent(m)
	if e != nil {
		return nil, e
	}
	if e = InstallCurrent(dir, current); e != nil {
		return nil, e
	}
	ok = true
	return &ThreadLog{file: file, writer: writer, header: h, manifest: m, state: candidate, dir: dir, end: int64(len(raw)), records: frameRecords(f)}, nil
}

// OpenThread はcurrentの必須位置を失わない場合だけ不完全末尾を切り詰める。
// 検証器のない入口ではbaseを拒否する。復旧候補の公開はevidence照合後に行う。
func OpenThread(parent string, owner domain.ID, key uint64) (*ThreadLog, error) {
	return OpenThreadWithPack(parent, owner, key, nil)
}

// OpenThreadWithPack はbase付き世代を外部の証拠検証器と照合してからdeltaを再生する。
func OpenThreadWithPack(parent string, owner domain.ID, key uint64, verify PackVerifier) (*ThreadLog, error) {
	dir := filepath.Join(parent, fmt.Sprint(key))
	for _, path := range []string{dir, filepath.Join(dir, "current.json")} {
		if e := privateRegular(path, path == dir); e != nil {
			return nil, e
		}
	}
	b, e := readBounded(filepath.Join(dir, "current.json"), 16<<10)
	if e != nil {
		return nil, e
	}
	m, e := DecodeCurrent(b)
	if e != nil || m.BoardID != owner || uint64(m.ThreadKey) != key {
		return nil, ErrCorrupt
	}
	var level, codec uint8
	var base *PackSnapshot
	var state *domain.Thread
	var records []ThreadRecord
	if m.Base != nil {
		if verify == nil {
			return nil, errors.New("pack evidence verifier required")
		}
		if _, _, e = InspectThreadFiles(dir); e != nil {
			return nil, e
		}
		packPath := filepath.Join(dir, m.Base.File)
		if e = privateRegular(packPath, false); e != nil {
			return nil, e
		}
		raw, e := readBounded(packPath, MaxPackFile)
		if e != nil {
			return nil, e
		}
		if uint64(len(raw)) != uint64(m.Base.Length) || sha256.Sum256(raw) != m.Base.SHA {
			return nil, ErrCorrupt
		}
		s, e := DecodePack(raw)
		if e != nil {
			return nil, e
		}
		if s.Owner != owner || s.Key != key || s.Generation != uint64(m.Generation) || s.State.Revision != m.Base.Seq || s.State.After.DATGeneration != m.Base.DATGeneration {
			return nil, ErrCorrupt
		}
		records, e = verify(s)
		if e != nil {
			return nil, e
		}
		if uint64(len(records)) != uint64(s.State.Revision) {
			return nil, ErrCorrupt
		}
		for i, r := range records {
			if r.Seq != domain.U64(i+1) {
				return nil, ErrCorrupt
			}
		}
		records = retainPackRecords(records, s.At)
		level = packMinimumLevel(raw)
		codec = packCompressionCodec(raw)
		base = &s
		state = s.State
	}
	path := filepath.Join(dir, m.Delta.File)
	if e = privateRegular(path, false); e != nil {
		return nil, e
	}
	file, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	h := Header{Owner: owner, Key: key, BaseSeq: uint64(m.Delta.BaseSeq), Generation: uint64(m.Generation)}
	end, partial, e := Scan(file, h, m.Delta, func(f Frame) error {
		next, e := applyFrame(state, f)
		if e == nil {
			state = next
			records = append(records, frameRecords(f)...)
		}
		return e
	})
	if e != nil || state == nil {
		if e == nil {
			e = ErrCorrupt
		}
		return nil, e
	}
	if partial {
		if e = file.Truncate(end); e != nil {
			return nil, e
		}
	}
	// 完全な末尾も、前processのWrite後・Sync前に停止した可能性がある。
	// 復旧したacceptedを他fileへ保存する前に、データと所有directoryを再同期する。
	if e = file.Sync(); e != nil {
		return nil, e
	}
	if e = SyncDirectory(dir); e != nil {
		return nil, e
	}
	if e = SyncDirectory(parent); e != nil {
		return nil, e
	}
	if _, e = file.Seek(end, io.SeekStart); e != nil {
		return nil, e
	}
	ok = true
	return &ThreadLog{file: file, writer: NewWriter(file), header: h, manifest: m, state: state, dir: dir, end: end, records: records, base: base, packLevel: level, packCodec: codec}, nil
}

// Append は候補全体を検証し、WAL Sync後に内部の復旧状態だけを更新する。
func (t *ThreadLog) Append(prepared []byte) CommitResult {
	f, e := decodeFrameView(prepared)
	if e != nil {
		return CommitResult{NotWritten, ErrCorrupt}
	}
	next, e := applyFrame(t.state, f)
	if e != nil {
		return CommitResult{NotWritten, e}
	}
	if err := t.Flush(); err != nil {
		return CommitResult{Unknown, err}
	}
	before := t.writer.Stats().Bytes
	r := t.writer.Commit(prepared)
	if r.Status == Durable {
		t.state = next
		t.end += int64(t.writer.Stats().Bytes - before)
		t.records = append(t.records, frameRecords(f)...)
	}
	return r
}

// State は所有ワーカーだけが参照する非公開の復旧候補。変更は禁止。
func (t *ThreadLog) State() *domain.Thread { return t.state }

// Close は共有本文のcheckpoint後にhandleを閉じる。同期失敗時もhandleは解放する。
func (t *ThreadLog) Close() error {
	if err := t.Flush(); err != nil {
		return errors.Join(err, t.file.Close())
	}
	return t.file.Close()
}
func applyFrame(old *domain.Thread, f Frame) (*domain.Thread, error) {
	candidate := old
	for i, r := range f.Records {
		next, o, e := domain.ApplyEncoded(candidate, r.JSON, r.DAT)
		if e != nil {
			return nil, e
		}
		if uint64(o.Revision) != f.FirstSeq+uint64(i) || len(f.Records) > 1 && o.Type != "append" {
			return nil, ErrCorrupt
		}
		candidate = next
	}
	return candidate, nil
}
func privateRegular(path string, directory bool) error {
	s, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if s.Mode()&os.ModeSymlink != 0 || s.IsDir() != directory || !directory && !s.Mode().IsRegular() {
		return errors.New("invalid storage file type")
	}
	if s.Mode().Perm()&0077 != 0 {
		return errors.New("storage must be private")
	}
	return nil
}
func readBounded(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e == nil && int64(len(b)) > max {
		return nil, ErrCorrupt
	}
	return b, e
}
func writeFull(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}
