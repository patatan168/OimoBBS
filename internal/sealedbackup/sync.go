// Dockerの完成記録から暗号化を進め、保存済みコピーの再送・期限回収もGoで行う。
package sealedbackup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// SyncOptions はホスト側の定期暗号化・転送。復号秘密鍵は指定しない。
type SyncOptions struct {
	Container, Image, Source, Output, Destination, Receiver, SSHConfig string
	Runner                                                             CommandRunner
	now                                                                func() time.Time
}

// Sync は保存先の排他下で検証・暗号化・再送・回収を進め、ログ取得の失敗も隠さない。
func Sync(ctx context.Context, o SyncOptions, out io.Writer) (err error) {
	if o.Container == "" || o.Image == "" || o.Source == "" || o.Output == "" {
		return errors.New("sync requires container, image, source and output")
	}
	if o.Destination != "" {
		if _, _, e := ParseDestination(o.Destination); e != nil {
			return e
		}
	}
	source, e := filepath.Abs(o.Source)
	if e != nil {
		return e
	}
	root, e := filepath.Abs(o.Output)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return e
	}
	lock, e := lockDirectory(root, ".lock")
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if o.Runner == nil {
		o.Runner = runCommand
	}
	if o.now == nil {
		o.now = time.Now
	}
	if e = discardLocalPartials(root); e != nil {
		return e
	}
	events, logsErr := readCompleted(ctx, o)
	verified := map[string]bool{}
	for _, m := range events {
		if m.ExpiresAtNS <= o.now().UnixNano() {
			continue
		}
		if e = syncEvent(ctx, o, root, source, m, out); e != nil {
			return errors.Join(logsErr, e)
		}
		verified[m.Name] = true
	}
	if e = syncLocalPairs(ctx, o, root, verified, out); e != nil {
		return errors.Join(logsErr, e)
	}
	return logsErr
}

// readCompleted は取得量と時間を制限し、実アプリの引用付きnanosecond時刻も読む。
func readCompleted(ctx context.Context, o SyncOptions) ([]Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output := &cappedBuffer{limit: 16 << 20}
	e := o.Runner(ctx, "docker", []string{"logs", "--since", "24h", "--tail", "10000", o.Container}, nil, output, output)
	if e != nil {
		return nil, fmt.Errorf("backup log retrieval failed: %w", e)
	}
	if output.overflow {
		return nil, errors.New("backup log output limit exceeded")
	}
	var result []Manifest
	scanner := bufio.NewScanner(bytes.NewReader(output.body))
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		var entry struct {
			Status      string `json:"status"`
			Name        string `json:"name"`
			Preparation *struct {
				Complete     bool `json:"complete"`
				RestoreReady bool `json:"restore_ready"`
				Capture      *struct {
					Expires json.RawMessage `json:"expires_at_ns"`
				} `json:"capture"`
			} `json:"preparation"`
		}
		if json.Unmarshal(scanner.Bytes(), &entry) != nil || entry.Status != "completed" || entry.Preparation == nil || !entry.Preparation.Complete || !backupName.MatchString(entry.Name) {
			continue
		}
		if entry.Preparation.Capture == nil {
			return nil, errors.New("completed backup capture missing")
		}
		raw := entry.Preparation.Capture.Expires
		var text string
		if len(raw) > 0 && raw[0] == '"' {
			if e = json.Unmarshal(raw, &text); e != nil {
				return nil, e
			}
		} else {
			text = string(raw)
		}
		expires, e := strconv.ParseInt(text, 10, 64)
		if e != nil {
			return nil, e
		}
		m := Manifest{entry.Name, "", expires, entry.Preparation.RestoreReady}
		result = append(result, m)
	}
	return result, scanner.Err()
}

// syncEvent は不正な完成記録を先に無効化し、同期済み暗号文の記録だけを公開する。
func syncEvent(ctx context.Context, o SyncOptions, root, source string, m Manifest, out io.Writer) error {
	target, manifest := filepath.Join(root, m.Name+".seal"), filepath.Join(root, m.Name+".json")
	old, e := LoadManifest(manifest)
	valid := e == nil && old.Name == m.Name && old.ExpiresAtNS == m.ExpiresAtNS && old.RestoreReady == m.RestoreReady
	if e != nil && !os.IsNotExist(e) {
		if _, statErr := checkPrivate(manifest, false); statErr != nil {
			return statErr
		}
	}
	if valid {
		digest, _, e := fileDigest(target, false)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		valid = e == nil && digest == old.SHA256
	}
	if !valid {
		if e = os.Remove(manifest); e != nil && !os.IsNotExist(e) {
			return e
		}
		if e = syncDirectory(root); e != nil {
			return e
		}
		tmp := filepath.Join(root, m.Name+".partial")
		defer os.Remove(tmp)
		f, e := openNewFile(tmp)
		if e != nil {
			return e
		}
		e = writeDurable(f, func(w io.Writer) error { return packContainer(ctx, o, source, m.Name, w) })
		if e != nil {
			return e
		}
		info, e := os.Stat(tmp)
		if e != nil {
			return e
		}
		if info.Size() == 0 {
			return errors.New("empty encrypted backup")
		}
		if e = os.Rename(tmp, target); e != nil {
			return e
		}
		if e = syncDirectory(root); e != nil {
			return e
		}
		m.SHA256, _, e = fileDigest(target, false)
		if e != nil {
			return e
		}
		if e = installLocalManifest(root, m); e != nil {
			return e
		}
		if _, e = fmt.Fprintf(out, "{\"sealed_backup\":%q,\"restore_ready\":%t}\n", m.Name, m.RestoreReady); e != nil {
			return e
		}
	}
	return syncDirectory(root)
}

// installLocalManifest は暗号文に対応する完成記録を同期して置換する。
func installLocalManifest(root string, m Manifest) error {
	path := filepath.Join(root, m.Name+".json.partial")
	defer os.Remove(path)
	f, e := openNewFile(path)
	if e != nil {
		return e
	}
	raw, e := marshalManifest(m)
	if e != nil {
		return errors.Join(e, f.Close())
	}
	if e = writeDurable(f, func(w io.Writer) error { return writeBytes(w, raw) }); e != nil {
		return e
	}
	if e = os.Rename(path, filepath.Join(root, m.Name+".json")); e != nil {
		return e
	}
	return syncDirectory(root)
}

// discardLocalPartials は排他下で既知の未完成名だけを回収する。
func discardLocalPartials(root string) error {
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	changed := false
	for _, entry := range entries {
		name := entry.Name()
		base, ok := strings.CutSuffix(name, ".json.partial")
		if !ok {
			base, ok = strings.CutSuffix(name, ".partial")
		}
		if !ok || !backupName.MatchString(base) {
			continue
		}
		if _, e = checkPrivate(filepath.Join(root, name), false); e != nil {
			return e
		}
		if e = os.Remove(filepath.Join(root, name)); e != nil {
			return e
		}
		changed = true
	}
	if changed {
		return syncDirectory(root)
	}
	return nil
}

// syncLocalPairs はDockerログに依存せず、保存済み記録から再送と期限回収を進める。
func syncLocalPairs(ctx context.Context, o SyncOptions, root string, verified map[string]bool, out io.Writer) error {
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !backupName.MatchString(name) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		m, e := LoadManifest(path)
		if e != nil {
			return e
		}
		target := filepath.Join(root, name+".seal")
		if m.Name != name {
			return errors.New("local backup name mismatch")
		}
		if m.ExpiresAtNS <= o.now().UnixNano() {
			if e = os.Remove(target); e != nil && !os.IsNotExist(e) {
				return e
			}
			if e = os.Remove(path); e != nil {
				return e
			}
			if e = syncDirectory(root); e != nil {
				return e
			}
			if _, e = fmt.Fprintf(out, "{\"expired_sealed_backup_removed\":%q}\n", name); e != nil {
				return e
			}
			continue
		}
		if o.Destination == "" {
			continue
		}
		if !verified[name] {
			hash, _, e := fileDigest(target, false)
			if e != nil {
				return e
			}
			if hash != m.SHA256 {
				return errors.New("invalid sealed backup pair")
			}
		}
		if e = syncDirectory(root); e != nil {
			return e
		}
		if _, e = Send(ctx, target, path, SendOptions{Destination: o.Destination, Receiver: o.Receiver, SSHConfig: o.SSHConfig, Runner: o.Runner}); e != nil {
			return e
		}
	}
	return nil
}
