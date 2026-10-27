// 非必須日別journalの初回署名frameを先行保存し、作成途中を同じbytesだけで再開する。
package evidence

import (
	"bytes"
	"fmt"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

var optionalCreationName = regexp.MustCompile(`^\.create-([0-9]{8})\.frame(\.tmp)?$`)

func (s *OptionalStore) after(stage string) error {
	if s.checkpoint == nil {
		return nil
	}
	return s.checkpoint(stage)
}

// createOptionalControl は署名frameのintentを先にSyncし、既知prefixだけを補完する。
func (s *OptionalStore) createOptionalControl(dir string, h store.Header, frame []byte, validate store.ValueValidator) (*store.ControlLog, error) {
	intent := filepath.Join(s.root, fmt.Sprintf(".create-%d.frame", h.Key))
	if e := writeOptionalAtomicIntent(intent, frame); e != nil {
		return nil, e
	}
	if e := s.after("optional:create_intent"); e != nil {
		return nil, e
	}
	log, e := store.CompleteControlCreation(dir, h, frame, validate)
	if e != nil {
		return nil, e
	}
	if e = s.after("optional:create_control"); e != nil {
		log.Close()
		return nil, e
	}
	if e = os.Remove(intent); e != nil {
		log.Close()
		return nil, e
	}
	if e = store.SyncDirectory(s.root); e != nil {
		log.Close()
		return nil, e
	}
	return log, nil
}

// writeOptionalAtomicIntent は同期済みの一意な候補だけをrenameし、不一致候補を上書きしない。
func writeOptionalAtomicIntent(path string, raw []byte) error {
	if saved, e := readOptionalPrivate(path, 1<<20); e == nil {
		if bytes.Equal(saved, raw) {
			return nil
		}
		return store.ErrCorrupt
	} else if !os.IsNotExist(e) {
		return e
	}
	temporary := path + ".tmp"
	if e := writeOptionalIntent(temporary, raw); e != nil {
		return e
	}
	if e := os.Rename(temporary, path); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(path))
}

func readOptionalPrivate(path string, limit int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		return nil, store.ErrCorrupt
	}
	return os.ReadFile(path)
}

// optionalCreationFrame は署名・所有者・日付・seqを正本作成前に全件検査する。
func (s *OptionalStore) optionalCreationFrame(day uint64, raw []byte) error {
	j := &Journal{owner: s.owner, day: day, keyID: 10, key: s.key, validate: s.validate}
	f, n, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil || n != int64(len(raw)) || f.FirstSeq != 1 {
		return store.ErrCorrupt
	}
	state, e := store.ApplyControl(store.ControlState{}, 8, f, j.validateValue)
	if e != nil {
		return e
	}
	return j.replayState(state)
}

// resumeOptionalCreations は署名済みcanonicalを再開する。未設置の不完全tmpだけを欠測として回収する。
func (s *OptionalStore) resumeOptionalCreations(readOnly bool) error {
	entries, e := os.ReadDir(s.root)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		match := optionalCreationName.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		day, e := strconv.ParseUint(match[1], 10, 64)
		if _, err := time.Parse("20060102", match[1]); e != nil || err != nil {
			return store.ErrCorrupt
		}
		canonical := filepath.Join(s.root, fmt.Sprintf(".create-%d.frame", day))
		raw, e := readOptionalPrivate(filepath.Join(s.root, entry.Name()), 1<<20)
		if os.IsNotExist(e) && match[2] != "" {
			continue // canonicalの処理で同じtmpを回収済み。
		}
		if e != nil {
			return e
		}
		if e = s.optionalCreationFrame(day, raw); e != nil {
			if match[2] == "" {
				return e
			}
			if readOnly {
				return store.ErrIncomplete
			}
			// tmpは正本作成を開始する前の候補。canonical/日別dirがあれば削除を許可しない。
			for _, path := range []string{canonical, filepath.Join(s.root, match[1])} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					return store.ErrCorrupt
				}
			}
			if e = os.Remove(filepath.Join(s.root, entry.Name())); e != nil {
				return e
			}
			if e = store.SyncDirectory(s.root); e != nil {
				return e
			}
			s.startupDiscarded++
			continue
		}
		if readOnly {
			return store.ErrIncomplete
		}
		if match[2] == "" {
			if candidate, err := readOptionalPrivate(canonical+".tmp", 1<<20); err == nil {
				if !bytes.Equal(candidate, raw) {
					return store.ErrCorrupt
				}
				if e = os.Remove(canonical + ".tmp"); e != nil {
					return e
				}
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		if match[2] != "" {
			if e = writeOptionalAtomicIntent(canonical, raw); e != nil {
				return e
			}
		}
		j := &Journal{owner: s.owner, day: day, keyID: 10, key: s.key, validate: s.validate}
		log, e := store.CompleteControlCreation(filepath.Join(s.root, match[1]), store.Header{Kind: 8, Owner: s.owner, Key: day, Generation: 1}, raw, j.validateValue)
		if e != nil {
			return e
		}
		if e = log.Close(); e != nil {
			return e
		}
		if e = os.Remove(canonical); e != nil && !os.IsNotExist(e) {
			return e
		}
		if e = store.SyncDirectory(s.root); e != nil {
			return e
		}
	}
	return nil
}

// reopenOptionalDay は保存不明の列を閉じ、保存済み署名正本から照合して再開する。
func (s *OptionalStore) reopenOptionalDay(day uint64) (*Journal, error) {
	if j := s.journals[day]; j != nil {
		if e := j.Close(); e != nil {
			return nil, e
		}
	}
	if e := s.resumeOptionalCreations(false); e != nil {
		return nil, e
	}
	j, e := OpenJournal(filepath.Join(s.root, fmt.Sprint(day)), s.owner, day, 10, s.key, s.validate)
	if e != nil {
		return nil, e
	}
	j.create = s.createOptionalControl
	j.optionalHold = s.holdLive
	s.journals[day] = j
	return j, nil
}
