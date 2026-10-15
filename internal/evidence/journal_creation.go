// 初回署名frameの作成intentから、同一bytesだけでjournal初期化を再開する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"time"
)

const journalCreationLimit int64 = 1 << 20

// JournalCreationIntentPath はjournalと同じ親領域の固定初期化intent名を返す。
func JournalCreationIntentPath(dir string) string {
	return filepath.Join(filepath.Dir(dir), "."+filepath.Base(dir)+".create.frame")
}

// OpenJournalWithCreationIntent は初回frameを先行Syncし、初期化途中を署名検査して再開する。
// 親領域の排他/認可/有効化intentは呼出元で保持する。通常追記の保存形式は変えない。
func OpenJournalWithCreationIntent(dir string, owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator, boundary func(string) error) (*Journal, error) {
	if e := validateJournalCreationParameters(owner, day, keyID, key, validate); e != nil {
		return nil, e
	}
	if boundary == nil {
		boundary = func(string) error { return nil }
	}
	if e := resumeJournalCreation(dir, owner, day, keyID, key, validate); e != nil {
		return nil, e
	}
	j, e := OpenJournal(dir, owner, day, keyID, key, validate)
	if e != nil {
		return nil, e
	}
	j.create = func(path string, h store.Header, frame []byte, check store.ValueValidator) (*store.ControlLog, error) {
		intent := JournalCreationIntentPath(path)
		if e := writeJournalCreationIntent(intent, frame); e != nil {
			return nil, e
		}
		if e := boundary("journal:create_intent"); e != nil {
			return nil, e
		}
		log, e := store.CompleteControlCreation(path, h, frame, check)
		if e != nil {
			return nil, e
		}
		if e = boundary("journal:create_control"); e != nil {
			_ = log.Close()
			return nil, e
		}
		if e = finishJournalCreation(intent); e != nil {
			_ = log.Close()
			return nil, e
		}
		return log, nil
	}
	return j, nil
}

// readJournalCreation は既知の私有regular fileを上限内だけ読む。
func readJournalCreation(path string) ([]byte, error) {
	return readJournalCreationFile(path, journalCreationLimit)
}

func readJournalCreationFile(path string, limit int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		return nil, store.ErrCorrupt
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if int64(len(raw)) > limit {
		return nil, errors.Join(store.ErrCorrupt, readErr, closeErr)
	}
	return raw, errors.Join(readErr, closeErr)
}

// writeJournalCreationIntent は同一bytesだけを再送し、候補と親directoryを先行同期する。
func writeJournalCreationIntent(path string, raw []byte) error {
	if len(raw) == 0 || int64(len(raw)) > journalCreationLimit {
		return store.ErrCorrupt
	}
	if saved, e := readJournalCreation(path); e == nil {
		if !bytes.Equal(saved, raw) {
			return store.ErrCorrupt
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	var n int
	n, e = f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = os.Rename(path+".tmp", path); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(path))
}

// creationJournal は初回署名/完全型/連鎖を正本補完より先に照合する。
func creationJournal(owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator, raw []byte) (*Journal, error) {
	if e := validateJournalCreationParameters(owner, day, keyID, key, validate); e != nil {
		return nil, e
	}
	j := &Journal{owner: owner, day: day, keyID: keyID, key: key, validate: validate}
	f, n, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil || n != int64(len(raw)) || f.FirstSeq != 1 || len(f.Records) != 1 {
		return nil, store.ErrCorrupt
	}
	state, e := store.ApplyControl(store.ControlState{}, 8, f, j.validateValue)
	if e != nil {
		return nil, e
	}
	if e = j.replayState(state); e != nil {
		return nil, e
	}
	return j, nil
}

// resumeJournalCreation は既知の初期prefixを補完し、正本同期後にだけintentを除去する。
func resumeJournalCreation(dir string, owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator) error {
	intent := JournalCreationIntentPath(dir)
	if e := recoverJournalCreationCandidate(dir, intent, owner, day, keyID, key, validate); e != nil {
		return e
	}
	raw, e := readJournalCreation(intent)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	j, e := creationJournal(owner, day, keyID, key, validate, raw)
	if e != nil {
		return e
	}
	if e = inspectJournalCreationDirectory(dir, j, raw); e != nil {
		return e
	}
	log, e := store.CompleteControlCreation(dir, store.Header{Kind: 8, Owner: owner, Key: day, Generation: 1}, raw, j.validateValue)
	if e != nil {
		return e
	}
	if e = log.Close(); e != nil {
		return e
	}
	return finishJournalCreation(intent)
}

// finishJournalCreation は確定済み候補の除去を親directoryへ同期する。
func finishJournalCreation(intent string) error {
	if e := os.Remove(intent); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(intent))
}

// recoverJournalCreationCandidate は署名済みtmpを採用し、作成前の不完全tmpだけを安全に除去する。
func recoverJournalCreationCandidate(dir, intent string, owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator) error {
	tmp := intent + ".tmp"
	raw, e := readJournalCreation(tmp)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	canonical, e := readJournalCreation(intent)
	if e == nil {
		j, e := creationJournal(owner, day, keyID, key, validate, canonical)
		if e != nil {
			return e
		}
		if !bytes.Equal(raw, canonical[:min(len(raw), len(canonical))]) {
			return store.ErrCorrupt
		}
		if e = inspectJournalCreationDirectory(dir, j, canonical); e != nil {
			return e
		}
		return finishJournalCreation(tmp)
	}
	if !os.IsNotExist(e) {
		return e
	}
	return recoverUninstalledJournalCreation(dir, intent, raw, owner, day, keyID, key, validate)
}

// recoverUninstalledJournalCreation は未設置領域だけで候補を採用し、不完全frameだけを破棄する。
func recoverUninstalledJournalCreation(dir, intent string, raw []byte, owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator) error {
	if _, e := os.Lstat(dir); !os.IsNotExist(e) {
		return store.ErrCorrupt
	}
	_, _, frameErr := store.ReadFrame(bytes.NewReader(raw))
	if errors.Is(frameErr, io.EOF) || errors.Is(frameErr, store.ErrIncomplete) {
		return finishJournalCreation(intent + ".tmp")
	}
	if _, e := creationJournal(owner, day, keyID, key, validate, raw); e != nil {
		return e
	}
	if e := os.Rename(intent+".tmp", intent); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(intent))
}

// inspectJournalCreationDirectory は初期frame以外の行/未知file/異なるprefixを補完前に拒否する。
func inspectJournalCreationDirectory(dir string, j *Journal, raw []byte) error {
	entries, e := privateJournalCreationDirectory(dir)
	if e != nil {
		return e
	}
	current := false
	for _, entry := range entries {
		if e = inspectJournalCreationEntry(dir, entry, j, raw); e != nil {
			return e
		}
		current = current || entry.Name() == "control.current"
	}
	if !current {
		return nil
	}
	return inspectJournalCreationCurrent(dir, j)
}

// inspectJournalCreationCurrent はcurrentが初期一行だけを指すことを非変更で確認する。
func inspectJournalCreationCurrent(dir string, j *Journal) error {
	state, e := store.InspectControl(dir, 8, j.owner, j.day, j.validateValue)
	if e != nil {
		return e
	}
	if state.Seq != 1 {
		return store.ErrCorrupt
	}
	return nil
}

// privateJournalCreationDirectory は不在だけを許し、私有領域の未知entry数を有界検査する。
func privateJournalCreationDirectory(dir string) ([]os.DirEntry, error) {
	info, e := os.Lstat(dir)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, store.ErrCorrupt
	}
	return readJournalCreationDirectory(dir)
}

// readJournalCreationDirectory は初期領域のentryを三件まで読み、過剰なfileとClose失敗を拒否する。
func readJournalCreationDirectory(dir string) ([]os.DirEntry, error) {
	f, e := os.Open(dir)
	if e != nil {
		return nil, e
	}
	entries, readErr := f.ReadDir(3)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > 2 {
		return nil, store.ErrCorrupt
	}
	return entries, nil
}

// inspectJournalCreationEntry は許可名/私有権限と署名frame由来のWAL prefixを照合する。
func inspectJournalCreationEntry(dir string, entry os.DirEntry, j *Journal, raw []byte) error {
	if entry.Name() != "control.current" && entry.Name() != "control-000001.wal" {
		return store.ErrCorrupt
	}
	info, e := entry.Info()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return store.ErrCorrupt
	}
	if entry.Name() == "control.current" {
		return nil
	}
	header, e := store.EncodeHeader(store.Header{Kind: 8, Owner: j.owner, Key: j.day, Generation: 1})
	if e != nil {
		return e
	}
	want := append(header, raw...)
	if info.Size() > int64(len(want)) {
		return store.ErrCorrupt
	}
	got, e := readJournalCreationFile(filepath.Join(dir, entry.Name()), journalCreationLimit+store.HeaderSize)
	if e != nil {
		return e
	}
	if !bytes.Equal(got, want[:min(len(got), len(want))]) {
		return store.ErrCorrupt
	}
	return nil
}

func validateJournalCreationParameters(owner domain.ID, day uint64, keyID uint32, key ed25519.PrivateKey, validate PayloadValidator) error {
	date := fmt.Sprint(day)
	if _, e := time.Parse("20060102", date); e != nil || len(date) != 8 {
		return store.ErrCorrupt
	}
	if owner == (domain.ID{}) || keyID == 0 || len(key) != ed25519.PrivateKeySize || validate == nil {
		return store.ErrCorrupt
	}
	return nil
}
