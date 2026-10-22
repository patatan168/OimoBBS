// 署名済み初期frameの先行保存から、案件作成中断を固定ID・同一bytesで再開する。
package disclosure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strings"
)

func (s *Store) intentPath(id domain.ID) string {
	return filepath.Join(s.root, ".create-"+id.String()+".frame")
}
func (s *Store) after(point string) error {
	if s.checkpoint != nil {
		return s.checkpoint(point)
	}
	return nil
}
func (s *Store) createLog(id domain.ID, frame []byte) (*store.ControlLog, error) {
	intent := s.intentPath(id)
	if e := writeArtifact(intent, frame); e != nil {
		return nil, e
	}
	if e := s.after("create:intent"); e != nil {
		return nil, e
	}
	path := filepath.Join(s.root, id.String())
	if e := prepareDir(path); e != nil {
		return nil, e
	}
	if e := s.after("create:directory"); e != nil {
		return nil, e
	}
	log, e := store.CompleteControlCreation(filepath.Join(path, "control"), store.Header{Kind: 9, Owner: id, Generation: 1}, frame, s.validator(id))
	if e != nil {
		return nil, e
	}
	if e = s.after("create:control"); e != nil {
		log.Close()
		return nil, e
	}
	if e = os.Remove(intent); e != nil {
		log.Close()
		return nil, e
	}
	if e = syncDir(s.root); e != nil {
		log.Close()
		return nil, e
	}
	if e = s.after("create:complete"); e != nil {
		log.Close()
		return nil, e
	}
	return log, nil
}
func (s *Store) resumeCreations() error {
	entries, e := os.ReadDir(s.root)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".create-") {
			continue
		}
		temporary := strings.HasSuffix(name, ".frame.tmp")
		canonical := strings.TrimSuffix(name, ".tmp")
		if !strings.HasSuffix(canonical, ".frame") || entry.IsDir() {
			return store.ErrCorrupt
		}
		var id domain.ID
		if json.Unmarshal([]byte(fmt.Sprintf("%q", strings.TrimSuffix(strings.TrimPrefix(canonical, ".create-"), ".frame"))), &id) != nil {
			return store.ErrCorrupt
		}
		raw, e := readArtifact(filepath.Join(s.root, name))
		if e != nil {
			return e
		}
		f, n, e := store.ReadFrame(bytes.NewReader(raw))
		if e != nil || n != int64(len(raw)) || f.FirstSeq != 1 {
			return store.ErrCorrupt
		}
		if _, e = store.ApplyControl(store.ControlState{}, 9, f, s.validator(id)); e != nil {
			return e
		}
		if temporary {
			if existing, err := readArtifact(s.intentPath(id)); err == nil {
				if !bytes.Equal(existing, raw) {
					return store.ErrCorrupt
				}
				if e = os.Remove(filepath.Join(s.root, name)); e != nil {
					return e
				}
			} else if os.IsNotExist(err) {
				if e = os.Rename(filepath.Join(s.root, name), s.intentPath(id)); e != nil {
					return e
				}
			} else {
				return err
			}
			if e = syncDir(s.root); e != nil {
				return e
			}
		}
		if _, err := os.Stat(s.intentPath(id)); os.IsNotExist(err) {
			continue
		}
		log, e := s.createLog(id, raw)
		if e != nil {
			return e
		}
		if e = log.Close(); e != nil {
			return e
		}
	}
	return nil
}
