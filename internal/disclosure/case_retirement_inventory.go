// 満了案件の署名済み候補と現在の物理制御正本を照合し、全保存世代の固定一覧を作る。
package disclosure

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxCaseRetirementFiles = 128

// CaseRetirementFile は案件内の制御fileの相対名・長さ・hash。本文や管理情報を含めない。
type CaseRetirementFile struct {
	Name  string      `json:"name"`
	Bytes domain.U64  `json:"bytes"`
	SHA   domain.Hash `json:"sha256"`
}

// InspectCaseRetirementFiles は物理正本の全署名と候補を照合し、旧保存世代も含む固定一覧を返す。
// 案件排他内で呼ぶ。元所有者の現在照合と一覧の先行署名保存は呼出元が別途行う。
// 未知file/残存コピー/変更候補を非変更で拒否し、ctx中断をhash走査でも確認する。
func (s *Store) InspectCaseRetirementFiles(ctx context.Context, candidate CaseRetirementCandidate, now time.Time) ([]CaseRetirementFile, error) {
	if s.stopped {
		return nil, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := s.checkPhysicalRetirementCandidate(candidate, now); e != nil {
		return nil, e
	}
	if e := s.checkRetirementDirectories(candidate.Case); e != nil {
		return nil, e
	}
	return s.retirementControlInventory(ctx, candidate.Case)
}

// checkPhysicalRetirementCandidate は物理全連鎖を現在候補へ束縛する。
func (s *Store) checkPhysicalRetirementCandidate(candidate CaseRetirementCandidate, now time.Time) error {
	path := filepath.Join(s.root, candidate.Case.String(), "control")
	state, e := store.InspectControl(path, 9, candidate.Case, 0, s.validator(candidate.Case))
	if e != nil {
		return e
	}
	var latest Audit
	var head evidence.Event
	if e = s.walkHistory(candidate.Case, state, func(a Audit, event evidence.Event) error { latest, head = a, event; return nil }); e != nil {
		return e
	}
	at := domain.Time(now.UnixNano())
	if at < latest.At {
		return ErrExpired
	}
	current, ready, e := planCaseRetirement(latest, head, at)
	if e != nil {
		return e
	}
	if !ready || current != candidate {
		return ErrRevision
	}
	return nil
}

func (s *Store) checkRetirementDirectories(id domain.ID) error {
	path := filepath.Join(s.root, id.String())
	if e := s.inspectCaseDirectories(id); e != nil {
		return e
	}
	names, e := os.ReadDir(path)
	if e != nil {
		return e
	}
	for _, entry := range names {
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if info.Mode().Perm() != 0700 {
			return store.ErrCorrupt
		}
		if entry.Name() == "control" {
			continue
		}
		children, e := os.ReadDir(filepath.Join(path, entry.Name()))
		if e != nil {
			return e
		}
		if len(children) != 0 {
			return store.ErrIncomplete
		}
	}
	return nil
}

func (s *Store) retirementControlInventory(ctx context.Context, id domain.ID) ([]CaseRetirementFile, error) {
	path := filepath.Join(s.root, id.String(), "control")
	names, e := retirementControlNames(path)
	if e != nil {
		return nil, e
	}
	files := []CaseRetirementFile{}
	var total uint64
	for _, name := range names {
		file, e := inspectRetirementControlFile(ctx, path, name, id)
		if e != nil {
			return nil, e
		}
		total += uint64(file.Bytes)
		if total > uint64(MaxStoredBytes) {
			return nil, ErrLimit
		}
		files = append(files, file)
	}
	return files, nil
}

func retirementControlNames(path string) ([]string, error) {
	dir, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	names, e := dir.Readdirnames(maxCaseRetirementFiles + 1)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(names) == 0 || len(names) > maxCaseRetirementFiles {
		return nil, ErrLimit
	}
	sort.Strings(names)
	return names, nil
}

// retirementGeneration はcanonicalな制御保存世代名だけを受け付ける。
func retirementGeneration(name string) (uint64, string, error) {
	suffix := filepath.Ext(name)
	if suffix != ".wal" && suffix != ".snap" {
		return 0, "", store.ErrCorrupt
	}
	text := strings.TrimSuffix(strings.TrimPrefix(name, "control-"), suffix)
	generation, e := strconv.ParseUint(text, 10, 64)
	if e != nil || generation == 0 || name != fmt.Sprintf("control-%06d%s", generation, suffix) {
		return 0, "", store.ErrCorrupt
	}
	return generation, suffix, nil
}

func inspectRetirementControlFile(ctx context.Context, path, name string, id domain.ID) (CaseRetirementFile, error) {
	file, size, e := openRetirementFile(filepath.Join(path, name))
	if e != nil {
		return CaseRetirementFile{}, e
	}
	defer file.Close()
	if e = checkRetirementControlHeader(file, name, id); e != nil {
		return CaseRetirementFile{}, e
	}
	hash, e := hashRetirementFile(ctx, file, size)
	if e != nil {
		return CaseRetirementFile{}, e
	}
	return CaseRetirementFile{Name: "control/" + name, Bytes: domain.U64(size), SHA: hash}, nil
}

// openRetirementFile はprivate regular fileと開いたinodeの一致を確認する。
func openRetirementFile(path string) (*os.File, int64, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, 0, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 {
		return nil, 0, store.ErrCorrupt
	}
	if !exclusiveRetirementFile(info) {
		return nil, 0, store.ErrCorrupt
	}
	if info.Size() > MaxStoredBytes {
		return nil, 0, ErrLimit
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, 0, e
	}
	actual, e := file.Stat()
	if e != nil || !os.SameFile(info, actual) {
		file.Close()
		return nil, 0, store.ErrCorrupt
	}
	return file, info.Size(), nil
}

func exclusiveRetirementFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func checkRetirementControlHeader(file *os.File, name string, id domain.ID) error {
	if name == "control.current" {
		return nil
	}
	generation, suffix, e := retirementGeneration(name)
	if e != nil {
		return e
	}
	raw := make([]byte, 64)
	if _, e = file.ReadAt(raw, 0); e != nil {
		return e
	}
	h, e := store.DecodeHeader(raw)
	if suffix == ".snap" {
		h, _, e = store.DecodeControlSnapshotHeader(raw)
	}
	if e != nil || h.Owner != id || h.Kind != 9 || h.Key != 0 || h.Generation != generation {
		return store.ErrCorrupt
	}
	return nil
}

// hashRetirementFile は固定scratchとctxでRAMへの全file読込みを避ける。
func hashRetirementFile(ctx context.Context, file *os.File, size int64) (domain.Hash, error) {
	h := sha256.New()
	scratch := make([]byte, 32<<10)
	var total int64
	for {
		if e := ctx.Err(); e != nil {
			return domain.Hash{}, e
		}
		n, e := file.Read(scratch)
		total += int64(n)
		if total > size {
			return domain.Hash{}, store.ErrCorrupt
		}
		if _, err := h.Write(scratch[:n]); err != nil {
			return domain.Hash{}, err
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return domain.Hash{}, e
		}
	}
	if total != size {
		return domain.Hash{}, store.ErrCorrupt
	}
	var digest domain.Hash
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
