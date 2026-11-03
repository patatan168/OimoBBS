// 有界な受信と検査を終えた一組だけを、完成世代へ原子的に設置する。
package sealedbackup

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Receiver は保存先ごとに排他する。各I/O境界は同じ実fileを使う障害検査に差し替えられる。
type Receiver struct {
	root       string
	now        func() time.Time
	openNew    func(string) (durableFile, error)
	syncDir    func(string) error
	rename     func(string, string) error
	removePair func(string) error
}

// NewReceiver は所有者限定の既存directoryを使う受信・期限回収の入口を作る。
func NewReceiver(root string) *Receiver {
	return &Receiver{root: root, now: time.Now, openNew: func(p string) (durableFile, error) { return openNewFile(p) }, syncDir: syncDirectory, rename: os.Rename, removePair: removePairDirectory}
}
func randomSuffix() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", id[:]), nil
}
func (r *Receiver) valid(h Header) error {
	if h.Protocol != 1 || h.Size <= 0 {
		return errors.New("invalid transfer header")
	}
	if e := h.Manifest.Validate(); e != nil {
		return e
	}
	if h.Manifest.ExpiresAtNS <= r.now().UnixNano() {
		return errors.New("expired backup")
	}
	return nil
}

// Receive は全fileの同期・Close・rename・親同期後だけACKを返す。既存の完成世代は上書きしない。
func (r *Receiver) Receive(source io.Reader, h Header) (ack Acknowledgement, err error) {
	if e := r.valid(h); e != nil {
		return ack, e
	}
	lock, e := lockDirectory(r.root, ".receive.lock")
	if e != nil {
		return ack, e
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if _, e = r.cleanUnfinished(); e != nil {
		return ack, e
	}
	if _, e = r.expireGenerations(); e != nil {
		return ack, e
	}
	final := filepath.Join(r.root, h.Manifest.Generation())
	if _, e = os.Lstat(final); e == nil {
		return r.receiveExisting(final, source, h)
	} else if !os.IsNotExist(e) {
		return ack, e
	}
	suffix, e := randomSuffix()
	if e != nil {
		return ack, e
	}
	stage := filepath.Join(r.root, ".incoming-"+h.Manifest.Generation()+"-"+suffix)
	if e = os.Mkdir(stage, 0700); e != nil {
		return ack, e
	}
	defer func() {
		if _, e := os.Lstat(stage); e == nil {
			err = errors.Join(err, r.removePair(stage), r.syncDir(r.root))
		} else if !os.IsNotExist(e) {
			err = errors.Join(err, e)
		}
	}()
	if e = r.writeCiphertext(filepath.Join(stage, "archive.seal"), source, h); e != nil {
		return ack, e
	}
	raw, e := marshalManifest(h.Manifest)
	if e != nil {
		return ack, e
	}
	f, e := r.openNew(filepath.Join(stage, "manifest.json"))
	if e != nil {
		return ack, e
	}
	if e = writeDurable(f, func(w io.Writer) error { return writeBytes(w, raw) }); e != nil {
		return ack, e
	}
	if e = r.syncDir(stage); e != nil {
		return ack, e
	}
	if e = r.valid(h); e != nil {
		return ack, e
	}
	if e = r.rename(stage, final); e != nil {
		return ack, e
	}
	if e = r.syncDir(r.root); e != nil {
		return ack, e
	}
	return acknowledgement(h.Manifest, "installed"), nil
}

// writeCiphertext は新規暗号文の全検査と同期を完了してから閉じる。
func (r *Receiver) writeCiphertext(path string, source io.Reader, h Header) error {
	f, e := r.openNew(path)
	if e != nil {
		return e
	}
	return writeDurable(f, func(w io.Writer) error { return consumeCiphertext(source, h, w) })
}

// consumeCiphertext は宣言した長さ・EOF・hashを検査し、任意の保存先へ流す。
func consumeCiphertext(source io.Reader, h Header, output io.Writer) error {
	digest := sha256.New()
	buf := make([]byte, 256<<10)
	remaining := h.Size
	for remaining > 0 {
		n, e := io.ReadFull(source, buf[:min(int64(len(buf)), remaining)])
		if e != nil {
			return e
		}
		if output != nil {
			if e = writeBytes(output, buf[:n]); e != nil {
				return e
			}
		}
		digest.Write(buf[:n])
		remaining -= int64(n)
	}
	var tail [1]byte
	n, e := source.Read(tail[:])
	if n != 0 || e != io.EOF {
		return errors.Join(errors.New("backup length mismatch"), e)
	}
	if fmt.Sprintf("%x", digest.Sum(nil)) != h.Manifest.SHA256 {
		return errors.New("backup hash mismatch")
	}
	return nil
}

// receiveExisting は保存先を書き直さず、受信内容も最後まで検証してACKを返す。
func (r *Receiver) receiveExisting(final string, source io.Reader, h Header) (Acknowledgement, error) {
	if e := r.verifyExisting(final, h); e != nil {
		return Acknowledgement{}, e
	}
	if e := consumeCiphertext(source, h, nil); e != nil {
		return Acknowledgement{}, e
	}
	if e := r.valid(h); e != nil {
		return Acknowledgement{}, e
	}
	if e := r.syncDir(r.root); e != nil {
		return Acknowledgement{}, e
	}
	return acknowledgement(h.Manifest, "existing"), nil
}

// verifyExisting は再利用する世代の内容・記録・長さを照合して同期する。
func (r *Receiver) verifyExisting(path string, h Header) error {
	if _, e := checkPrivate(path, true); e != nil {
		return e
	}
	entries, e := os.ReadDir(path)
	if e != nil {
		return e
	}
	if len(entries) != 2 {
		return errors.New("unexpected backup generation files")
	}
	m, e := LoadManifest(filepath.Join(path, "manifest.json"))
	if e != nil || m != h.Manifest {
		return errors.Join(errors.New("existing manifest mismatch"), e)
	}
	digest, size, e := fileDigest(filepath.Join(path, "archive.seal"), true)
	if e != nil {
		return e
	}
	if size != h.Size || digest != m.SHA256 {
		return errors.New("existing backup integrity mismatch")
	}
	f, e := openPrivate(filepath.Join(path, "manifest.json"))
	if e != nil {
		return e
	}
	if e = errors.Join(f.Sync(), f.Close()); e != nil {
		return e
	}
	return r.syncDir(path)
}
