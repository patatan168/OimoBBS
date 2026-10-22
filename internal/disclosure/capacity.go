// 案件領域の総量を制限し、未知pathや過大コピーを容量計算から除外しない。
package disclosure

import (
	"io/fs"
	"os"
	"path/filepath"
)

const MaxStoredBytes int64 = 256 << 20

func (s *Store) requireCapacity(additional int64) error {
	var size int64
	e := filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return ErrInvalid
		}
		size += info.Size()
		if size > MaxStoredBytes-additional {
			return ErrLimit
		}
		return nil
	})
	return e
}
