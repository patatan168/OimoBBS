// 起動時と同期保存後に監査/jobの参照を登録し、捕捉時のfilesystem走査を避ける。
package bootstrap

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

type onlineCatalogPart struct {
	kind      string
	owner     domain.ID
	subkey    string
	expires   domain.Time
	reference store.ControlBackupReference
}
type onlineCatalog struct {
	parts    map[string]onlineCatalogPart
	metadata map[string][]byte
}

// registerOnlineLog は所有者排他の下で呼び、確定済み参照と元期限だけを登録する。
func (r *Repository) registerOnlineLog(kind string, owner domain.ID, subkey string, log *store.ControlLog) error {
	if r.onlineCatalog == nil {
		return nil
	}
	var expires domain.Time
	for _, row := range log.State().Rows {
		if row.Expires != nil && (expires == 0 || *row.Expires < expires) {
			expires = *row.Expires
		}
	}
	reference, err := log.BackupReference(expires)
	if err != nil {
		return err
	}
	key := kind + "/" + owner.String() + "/" + subkey
	r.onlineCatalog.parts[key] = onlineCatalogPart{kind, owner, subkey, expires, reference}
	return nil
}

// loadOnlineCatalog は検査済み起動時だけ所有者を列挙し、payloadを再生して参照を登録する。
func (r *Repository) loadOnlineCatalog() error {
	r.onlineCatalog = &onlineCatalog{parts: map[string]onlineCatalogPart{}, metadata: map[string][]byte{}}
	dirs, err := siteDirectories(r.site.State())
	if err != nil {
		return err
	}
	ids, err := childIDs(filepath.Join(r.cfg.DataDir, "jobs"))
	if err != nil {
		return err
	}
	for _, id := range ids {
		log, e := store.OpenControl(filepath.Join(r.cfg.DataDir, "jobs", id.String()), 6, id, 0, validateProvisionJob)
		if e != nil {
			return e
		}
		e = r.registerOnlineLog("job", id, "control", log)
		if e = errors.Join(e, log.Close()); e != nil {
			return e
		}
	}
	owners, err := childIDs(filepath.Join(r.cfg.DataDir, "audit"))
	if err != nil {
		return err
	}
	for _, id := range owners {
		kind := "board"
		if id == siteID(r.site.State()) {
			kind = "site"
		} else if dirs[id] == nil {
			return store.ErrCorrupt
		}
		names, e := boundedAuditNames(filepath.Join(r.cfg.DataDir, "audit", id.String()), 10000)
		if e != nil {
			return e
		}
		for _, day := range names {
			subkey, e := strconv.ParseUint(day, 10, 64)
			if e != nil {
				return e
			}
			log, e := store.OpenControl(filepath.Join(r.cfg.DataDir, "audit", id.String(), day), 4, id, subkey, auditValueValidator(id, kind, day))
			if e != nil {
				return e
			}
			e = r.registerOnlineLog("audit", id, day, log)
			if e = errors.Join(e, log.Close()); e != nil {
				return e
			}
		}
	}
	paths := []string{"instance.json"}
	for id, anchor := range r.anchors {
		path := filepath.Join(controlOwnerPath(r.cfg.DataDir, anchor.Kind, id), fmt.Sprintf("control-%06d.anchor.json", anchor.Generation))
		rel, e := filepath.Rel(r.cfg.DataDir, path)
		if e != nil {
			return e
		}
		paths = append(paths, filepath.ToSlash(rel))
	}
	for _, name := range paths {
		raw, e := readPrivate(filepath.Join(r.cfg.DataDir, filepath.FromSlash(name)), backupManifestLimit)
		if e != nil {
			return e
		}
		r.onlineCatalog.metadata[name] = raw
	}
	return nil
}

// rememberAuditLog は日別sinkを閉じる前に確定境界を登録する。呼出元は管理mutexを保持する。
func (r *Repository) rememberAuditLog(path string, log *store.ControlLog) error {
	parts := strings.Split(filepath.ToSlash(path), "/")
	if len(parts) < 2 {
		return store.ErrCorrupt
	}
	owner, e := parseCatalogID(parts[len(parts)-2])
	if e != nil {
		return e
	}
	return r.registerOnlineLog("audit", owner, parts[len(parts)-1], log)
}

func parseCatalogID(raw string) (domain.ID, error) {
	var id domain.ID
	err := id.UnmarshalJSON([]byte(strconv.Quote(raw)))
	return id, err
}

// catalogMetadataBytes は小さな固定metadata全体の容量を確認する。
func catalogMetadataBytes(values map[string][]byte) (uint64, error) {
	var total uint64
	for name, raw := range values {
		if !safeBackupName(name) || len(raw) == 0 || uint64(len(raw)) > backupManifestLimit-total {
			return 0, store.ErrHistoryBudget
		}
		total += uint64(len(raw))
	}
	return total, nil
}
