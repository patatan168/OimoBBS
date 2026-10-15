// HTTP保全の既知copy集合だけを許可し、検査や起動で未知artifactを消さない。
package disclosure

import (
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// inspectHTTPArtifacts は元期限と独立に、private mode・固定名・保全hash/署名を検査する。
func (s *Store) inspectHTTPArtifacts(c Case, allowPending bool) error {
	dir := s.artifactDir(c.ID, "http")
	info, e := os.Lstat(dir)
	if os.IsNotExist(e) {
		if c.HTTP != nil && c.HTTP.State == "preparing" && c.State != "releasing" && c.State != "closed" {
			if !allowPending {
				return store.ErrIncomplete
			}
			return nil
		}
		if c.HTTP == nil || c.State == "releasing" || c.State == "closed" {
			return nil
		}
		return store.ErrCorrupt
	}
	if e != nil {
		return e
	}
	if c.HTTP == nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	if c.State == "closed" {
		return store.ErrCorrupt
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	known := map[string]bool{}
	for _, item := range c.HTTP.Items {
		known[item.Record.String()+".json"] = true
	}
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		pending := filepath.Ext(name) == ".tmp"
		base := name
		if pending {
			base = name[:len(name)-4]
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !known[base] || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > evidence.MaxOptionalQueryBytes {
			return store.ErrCorrupt
		}
		total += info.Size()
		if total > 2*evidence.MaxOptionalQueryBytes {
			return ErrLimit
		}
		if pending && !allowPending {
			return store.ErrIncomplete
		}
		if pending && c.HTTP.State != "preparing" && c.HTTP.State != "partial" {
			return store.ErrCorrupt
		}
	}
	if c.State == "releasing" || c.State == "closed" {
		return nil
	}
	if c.HTTP.State == "preparing" {
		if !allowPending {
			return store.ErrIncomplete
		}
		return nil
	}
	ops, e := s.httpOperations(c, time.Unix(0, int64(c.Created)))
	if e != nil {
		return e
	}
	_, e = s.readHTTPRecords(c, ops)
	return e
}
