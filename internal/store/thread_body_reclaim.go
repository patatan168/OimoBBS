// 公開本体の回収元を固定し、先行証明後の途中停止から既知ファイルだけを除去する。
package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"oimobbs/internal/domain"
)

// BodySourceFile は公開本体の固定参照。任意pathや公開本文を含まない。
type BodySourceFile struct {
	Name   string      `json:"name"`
	Length domain.U64  `json:"length"`
	SHA    domain.Hash `json:"sha256"`
}

// DedupRetentionFloor は満了回収した再送索引を時計逆行で復活させない基準時刻。
func (t *ThreadLog) DedupRetentionFloor() domain.Time {
	if t.base != nil {
		return t.base.At
	}
	return 0
}

// BodySourceFiles は現行currentを照合し、旧世代・中断候補を含む公開本体の参照を固定する。
func (t *ThreadLog) BodySourceFiles(ctx context.Context) ([]BodySourceFile, error) {
	m, _, e := InspectThreadFiles(t.dir)
	if e != nil {
		return nil, e
	}
	a, _ := EncodeCurrent(m)
	b, _ := EncodeCurrent(t.manifest)
	if string(a) != string(b) {
		return nil, ErrCorrupt
	}
	names, e := bodyFileNames(t.dir)
	if e != nil {
		return nil, e
	}
	out := make([]BodySourceFile, 0, len(names))
	for _, name := range names {
		v, e := hashBodyFile(ctx, t.dir, name)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}

// ValidateBodySourceFiles は署名対象の固定参照を構造検査する。
func ValidateBodySourceFiles(files []BodySourceFile) error {
	if len(files) < 2 || len(files) > 4096 {
		return ErrCorrupt
	}
	current := false
	for i, v := range files {
		if !bodyFileName(v.Name) || v.Length > 32<<30 || v.SHA == (domain.Hash{}) || i > 0 && files[i-1].Name >= v.Name {
			return ErrCorrupt
		}
		current = current || v.Name == "current.json"
	}
	if !current {
		return ErrCorrupt
	}
	return nil
}

func bodyFileName(name string) bool {
	if len(name) > 255 || name != filepath.Base(name) || strings.ContainsAny(name, "\\\x00") {
		return false
	}
	if name == "current.json" || strings.HasPrefix(name, ".install-") && len(name) > 9 {
		return true
	}
	prefix, suffix := "delta-", ".wal"
	if strings.HasPrefix(name, "base-") {
		prefix, suffix = "base-", ".pack"
	}
	n, e := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix), 10, 64)
	return e == nil && n > 0 && name == fmt.Sprintf("%s%06d%s", prefix, n, suffix)
}

func bodyFileNames(dir string) ([]string, error) {
	if e := privateRegular(dir, true); e != nil {
		return nil, e
	}
	f, e := os.Open(dir)
	if e != nil {
		return nil, e
	}
	names, e := f.Readdirnames(4097)
	e = errors.Join(func() error {
		if e == io.EOF {
			return nil
		}
		return e
	}(), f.Close())
	if e != nil {
		return nil, e
	}
	if len(names) > 4096 {
		return nil, ErrCorrupt
	}
	sort.Strings(names)
	return names, nil
}

func hashBodyFile(ctx context.Context, dir, name string) (BodySourceFile, error) {
	if !bodyFileName(name) {
		return BodySourceFile{}, ErrCorrupt
	}
	path := filepath.Join(dir, name)
	if e := privateRegular(path, false); e != nil {
		return BodySourceFile{}, e
	}
	f, e := os.Open(path)
	if e != nil {
		return BodySourceFile{}, e
	}
	defer f.Close()
	h := sha256.New()
	var length int64
	buf := make([]byte, 64<<10)
	for {
		if e = ctx.Err(); e != nil {
			return BodySourceFile{}, e
		}
		n, err := f.Read(buf)
		length += int64(n)
		if length > 32<<30 {
			return BodySourceFile{}, ErrCorrupt
		}
		h.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return BodySourceFile{}, err
		}
	}
	var sha domain.Hash
	copy(sha[:], h.Sum(nil))
	return BodySourceFile{name, domain.U64(length), sha}, nil
}

// CheckReclaimedBody は先行証明の既知ファイルだけを許し、途中回収の欠落を許す。
// 未知ファイル・symlink・改変があれば全体を保持してエラーにする。
func CheckReclaimedBody(ctx context.Context, dir string, files []BodySourceFile) error {
	if e := ValidateBodySourceFiles(files); e != nil {
		return e
	}
	names, e := bodyFileNames(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	known := map[string]BodySourceFile{}
	for _, v := range files {
		known[v.Name] = v
	}
	for _, name := range names {
		want, ok := known[name]
		if !ok {
			return ErrCorrupt
		}
		got, e := hashBodyFile(ctx, dir, name)
		if e != nil {
			return e
		}
		if got != want {
			return ErrCorrupt
		}
	}
	return nil
}

// RemoveReclaimedBody は呼出元が署名と元受理記録を照合した後にだけ呼ぶ。
// 全残存ファイルの照合後にunlinkし、各保存境界の停止を同じ証明から再開できる。
func RemoveReclaimedBody(ctx context.Context, dir string, files []BodySourceFile, boundary func(string) error) error {
	if e := CheckReclaimedBody(ctx, dir, files); e != nil {
		return e
	}
	names, e := bodyFileNames(dir)
	if os.IsNotExist(e) {
		return SyncDirectory(filepath.Dir(dir))
	}
	if e != nil {
		return e
	}
	for _, name := range names {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = os.Remove(filepath.Join(dir, name)); e != nil {
			return e
		}
		if boundary != nil {
			if e = boundary("reclaim:file"); e != nil {
				return e
			}
		}
	}
	if e = SyncDirectory(dir); e != nil {
		return e
	}
	if boundary != nil {
		if e = boundary("reclaim:files_synced"); e != nil {
			return e
		}
	}
	if e = os.Remove(dir); e != nil {
		return e
	}
	if e = SyncDirectory(filepath.Dir(dir)); e != nil {
		return e
	}
	if boundary != nil {
		return boundary("reclaim:parent_synced")
	}
	return nil
}
