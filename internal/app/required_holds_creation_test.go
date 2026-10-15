// 初期化の署名intent・不完全候補・正本prefixを実fileで検査し、有効化済み領域を補完しない。
package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func stoppedRequiredHoldCreation(t *testing.T, stage string) (retirementFixture, string, []byte, domain.Time) {
	t.Helper()
	f := newRetirementFixture(t)
	path := filepath.Join(filepath.Dir(f.path), "required-holds")
	h, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, false)
	if e != nil {
		t.Fatal(e)
	}
	h.initializationCheckpoint = func(point string) error {
		if point == stage {
			return store.ErrIncomplete
		}
		return nil
	}
	now := f.until - 1
	if e = h.Initialize(now); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("stop ignored", e)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(evidence.JournalCreationIntentPath(path))
	if e != nil {
		t.Fatal(e)
	}
	return f, path, raw, now
}

func requiredCreationFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	if _, e := os.Lstat(path); e == nil {
		for name, raw := range retirementFiles(t, path) {
			files[name] = raw
		}
	} else if !os.IsNotExist(e) {
		t.Fatal(e)
	}
	intent := evidence.JournalCreationIntentPath(path)
	for _, name := range []string{intent, intent + ".tmp"} {
		raw, e := os.ReadFile(name)
		if e == nil {
			files[filepath.Base(name)] = raw
		} else if !os.IsNotExist(e) {
			t.Fatal(e)
		}
	}
	return files
}

func TestRequiredHoldCreationResumeSameSignedBytes(t *testing.T) {
	for _, stage := range []string{"journal:create_intent", "journal:create_control", "partial_wal", "empty_dir", "complete_tmp", "duplicate_tmp", "prefix_tmp"} {
		t.Run(stage, func(t *testing.T) {
			stop := "journal:create_intent"
			if stage == "journal:create_control" || stage == "partial_wal" {
				stop = "journal:create_control"
			}
			f, path, raw, now := stoppedRequiredHoldCreation(t, stop)
			intent := evidence.JournalCreationIntentPath(path)
			switch stage {
			case "partial_wal":
				wal := filepath.Join(path, "control-000001.wal")
				full, e := os.ReadFile(wal)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(filepath.Join(path, "control.current")); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(wal, full[:40], 0600); e != nil {
					t.Fatal(e)
				}
			case "empty_dir":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "complete_tmp", "duplicate_tmp", "prefix_tmp":
				tmp := raw
				if stage == "prefix_tmp" {
					tmp = raw[:13]
				}
				if e := os.WriteFile(intent+".tmp", tmp, 0600); e != nil {
					t.Fatal(e)
				}
				if stage == "complete_tmp" {
					if e := os.Remove(intent); e != nil {
						t.Fatal(e)
					}
				}
			}
			before := requiredCreationFiles(t, path)
			if _, e := InspectRequiredOriginalHolds(path, f.owner, 10, f.key); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("read-only completed pending creation", e)
			}
			if h, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, true); e == nil {
				h.Close()
				t.Fatal("active creation repaired")
			}
			if !reflect.DeepEqual(before, requiredCreationFiles(t, path)) {
				t.Fatal("inspection or active open changed bytes")
			}
			h, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, false)
			if e != nil {
				t.Fatal(e)
			}
			defer h.Close()
			if !h.initialized || h.floor != now {
				t.Fatal("initialization changed")
			}
			if e = h.Initialize(now + 1); e != nil {
				t.Fatal(e)
			}
			if len(h.journal.Entries()) != 1 {
				t.Fatal("initialization replay appended")
			}
			header, e := store.EncodeHeader(store.Header{Kind: 8, Owner: requiredHoldsOwner(f.owner), Key: requiredHoldsDay, Generation: 1})
			if e != nil {
				t.Fatal(e)
			}
			wal, e := os.ReadFile(filepath.Join(path, "control-000001.wal"))
			if e != nil || !bytes.Equal(wal, append(header, raw...)) {
				t.Fatal("recovered signature bytes changed", e)
			}
			for _, name := range []string{intent, intent + ".tmp"} {
				if _, e := os.Lstat(name); !os.IsNotExist(e) {
					t.Fatal("candidate remains", e)
				}
			}
			if _, e = InspectRequiredOriginalHolds(path, f.owner, 10, f.key); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestRequiredHoldCreationRefusesUnknownOrMismatchedSource(t *testing.T) {
	for _, stage := range []string{"foreign_owner", "foreign_key_id", "corrupt_canonical", "corrupt_complete_tmp", "invalid_signature_tmp", "invalid_schema_tmp", "unknown_file", "bad_wal_prefix", "later_history"} {
		t.Run(stage, func(t *testing.T) {
			stop := "journal:create_intent"
			if stage == "bad_wal_prefix" || stage == "later_history" {
				stop = "journal:create_control"
			}
			f, path, raw, now := stoppedRequiredHoldCreation(t, stop)
			board, keyID := f.owner, uint32(10)
			intent := evidence.JournalCreationIntentPath(path)
			switch stage {
			case "foreign_owner":
				board = domain.NewID()
			case "foreign_key_id":
				keyID = 11
			case "corrupt_canonical", "corrupt_complete_tmp":
				raw[len(raw)-1] ^= 1
				name := intent
				if stage == "corrupt_complete_tmp" {
					name += ".tmp"
					if e := os.Remove(intent); e != nil {
						t.Fatal(e)
					}
				}
				if e := os.WriteFile(name, raw, 0600); e != nil {
					t.Fatal(e)
				}
			case "invalid_signature_tmp", "invalid_schema_tmp":
				if e := os.Remove(intent); e != nil {
					t.Fatal(e)
				}
				invalid := invalidRequiredCreationFrame(t, f, raw, stage)
				if e := os.WriteFile(intent+".tmp", invalid, 0600); e != nil {
					t.Fatal(e)
				}
			case "unknown_file":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(path, "unknown"), []byte("unknown"), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(intent+".tmp", raw[:13], 0600); e != nil {
					t.Fatal(e)
				}
			case "bad_wal_prefix":
				if e := os.Remove(filepath.Join(path, "control.current")); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(path, "control-000001.wal"), []byte("different prefix"), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(intent+".tmp", raw[:13], 0600); e != nil {
					t.Fatal(e)
				}
			case "later_history":
				if e := os.Remove(intent); e != nil {
					t.Fatal(e)
				}
				h, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, true)
				if e != nil {
					t.Fatal(e)
				}
				rows, e := AcceptedRecords([]*evidence.Journal{f.journal})
				if e != nil {
					t.Fatal(e)
				}
				b := RequiredHoldBinding{Case: domain.NewID(), Revision: 2, Board: f.owner, From: f.identity.Committed - 1, To: f.identity.Committed + 1, Until: f.until + 1}
				if _, e = h.Reserve(b, rows, map[uint64]*evidence.Journal{20231114: f.journal}, now); e != nil {
					t.Fatal(e)
				}
				if e = h.Close(); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(intent, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := requiredCreationFiles(t, path)
			if h, e := OpenRequiredOriginalHolds(path, board, keyID, f.key, false); e == nil {
				h.Close()
				t.Fatal("invalid creation repaired")
			}
			if !reflect.DeepEqual(before, requiredCreationFiles(t, path)) {
				t.Fatal("refusal changed source bytes")
			}
		})
	}
}

func TestRequiredHoldCreationDiscardsOnlyUninstalledIncompleteCandidate(t *testing.T) {
	for _, n := range []int{0, 1, 7, 8, 40} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			f, path, raw, now := stoppedRequiredHoldCreation(t, "journal:create_intent")
			intent := evidence.JournalCreationIntentPath(path)
			if e := os.Remove(intent); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(intent+".tmp", raw[:n], 0600); e != nil {
				t.Fatal(e)
			}
			h, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, false)
			if e != nil {
				t.Fatal(e)
			}
			defer h.Close()
			if h.initialized {
				t.Fatal("partial candidate became initialized")
			}
			if e = h.Initialize(now); e != nil {
				t.Fatal(e)
			}
			if len(h.journal.Entries()) != 1 {
				t.Fatal("partial candidate replayed")
			}
		})
	}
}

// invalidRequiredCreationFrame はCRCを有効なまま再符号化し、署名または完全型の検査を独立に確認する。
func invalidRequiredCreationFrame(t *testing.T, f retirementFixture, raw []byte, stage string) []byte {
	t.Helper()
	frame, _, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	var op store.ControlOperation
	if e = json.Unmarshal(frame.Records[0].JSON, &op); e != nil {
		t.Fatal(e)
	}
	var event evidence.Event
	if e = json.Unmarshal(op.Mutations[0].Value, &event); e != nil {
		t.Fatal(e)
	}
	if stage == "invalid_signature_tmp" {
		sig, e := base64.StdEncoding.DecodeString(event.Signature)
		if e != nil {
			t.Fatal(e)
		}
		sig[0] ^= 1
		event.Signature = base64.StdEncoding.EncodeToString(sig)
	} else {
		payload, e := base64.StdEncoding.DecodeString(event.Payload)
		if e != nil {
			t.Fatal(e)
		}
		var p requiredHoldPayload
		if e = json.Unmarshal(payload, &p); e != nil {
			t.Fatal(e)
		}
		p.Schema = "unknown-hold-schema"
		payload, e = json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		event, e = evidence.Seal(evidence.Source{Owner: requiredHoldsOwner(f.owner), Subkey: requiredHoldsDay, Seq: 1}, event.RecordID, event.Kind, payload, event.PreviousSHA, 10, f.key)
		if e != nil {
			t.Fatal(e)
		}
	}
	op.Mutations[0].Value, e = json.Marshal(event)
	if e != nil {
		t.Fatal(e)
	}
	frame.Records[0].JSON, e = json.Marshal(op)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := store.EncodeFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	return encoded
}
