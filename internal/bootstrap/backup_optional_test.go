// 通常backupのHTTP記録除外、署名境界、隔離再生と通常起動の履歴保護を検証する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestBackupOptionalOmissionRoundTrip(t *testing.T) {
	for _, online := range []bool{false, true} {
		t.Run(map[bool]string{false: "offline", true: "online"}[online], func(t *testing.T) {
			ctx := context.Background()
			cfg, r := adminFixture(t)
			defer r.Close()
			site := siteID(r.site.State())
			s := optionalProductServer(t, r)
			req, e := http.NewRequest("GET", s.URL+"/", nil)
			if e != nil {
				t.Fatal(e)
			}
			req.Header.Set("User-Agent", "PRIVATE_HTTP_BACKUP_UA")
			response, e := s.Client().Do(req)
			if e != nil {
				t.Fatal(e)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			s.Close()
			if _, e = r.enableStorageReader(ctx, 42, "test_backup_optional_holds_enable"); e != nil {
				t.Fatal(e)
			}
			if e = r.ensureOptionalHoldStorage(ctx); e != nil {
				t.Fatal(e)
			}
			body, keys, work := onlineOutput(t, "body"), onlineOutput(t, "keys"), filepath.Dir(onlineOutput(t, "work-unused"))
			var report BackupReport
			if online {
				syncOnlineAudit(t, r)
				trust, plan := onlineOutput(t, "trust.json"), onlineOutput(t, "plan.json")
				marker, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
				if e != nil {
					t.Fatal(e)
				}
				if e = writeNew(trust, marker); e != nil {
					t.Fatal(e)
				}
				report, e = r.CaptureOnlineBackup(ctx, body, trust, plan, OnlineBackupSiteOptions{})
				if e != nil {
					t.Fatal(e)
				}
				if e = r.Close(); e != nil {
					t.Fatal(e)
				}
			} else {
				if e = r.Close(); e != nil {
					t.Fatal(e)
				}
				report, e = CaptureOfflineBackup(ctx, cfg, body)
				if e != nil {
					t.Fatal(e)
				}
			}
			if !report.Verified || !report.OptionalHTTPLogsOmitted || report.RestoreReady {
				t.Fatal(report)
			}
			records := optionalProductRecords(t, cfg, site)
			if len(records) == 0 || records[0].UserAgent == nil {
				t.Fatal("source record absent", records)
			}
			key, e := backupKey(cfg.DataDir)
			if e != nil {
				t.Fatal(e)
			}
			defer clear(key[:])
			raw, e := readPrivate(filepath.Join(body, "manifest.json"), backupManifestLimit)
			if e != nil {
				t.Fatal(e)
			}
			m, _, e := decodeBackupManifest(raw, key, site)
			if e != nil {
				t.Fatal(e)
			}
			expected := uint32(7)
			if m.Schema != expected {
				t.Fatal(m.Schema)
			}
			var omission string
			for _, entry := range m.Entries {
				for _, file := range entry.Files {
					path := filepath.Join(body, filepath.FromSlash(backupEntryPath(entry)), file.Name)
					data, e := os.ReadFile(path)
					if e != nil {
						t.Fatal(e)
					}
					if strings.Contains(string(data), "PRIVATE_HTTP_BACKUP_UA") {
						t.Fatal("HTTP payload copied", path)
					}
					if file.Name == backupOptionalOmissionName {
						omission = path
					}
				}
			}
			if omission == "" {
				t.Fatal("omission absent")
			}
			if _, e = ExportBackupKeys(ctx, cfg, body, keys); e != nil {
				t.Fatal(e)
			}
			if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
				t.Fatal(e)
			}
			defer os.Rename(cfg.DataDir+"-unavailable", cfg.DataDir)
			checked := false
			replay, e := verifyBackupReplay(ctx, body, keys, work, time.Now, func(root string) error {
				checked = true
				state, e := inspectRuntimeControl(root, "site", site)
				if e != nil {
					return e
				}
				var ss siteState
				if e = strictjson.Decode(state.Rows["site:state"].Value, &ss); e != nil {
					return e
				}
				probe := cfg
				probe.DataDir = root
				if e = inspectOptionalLogs(probe, ss, state, true); e == nil || !strings.Contains(e.Error(), "excluded HTTP logs") {
					t.Fatalf("normal log startup accepted omitted history: %v", e)
				}
				return nil
			})
			if e != nil || !checked || !replay.Replayed || !replay.OptionalHTTPLogsOmitted || replay.RestoreReady {
				t.Fatal(replay, e)
			}
			entries, e := os.ReadDir(work)
			if e != nil || len(entries) != 0 {
				t.Fatal("replay cleanup incomplete", entries, e)
			}
			// manifestのfile SHAを作り直しても、署名説明の改変は受け入れない。
			omissionRaw, e := os.ReadFile(omission)
			if e != nil {
				t.Fatal(e)
			}
			var env backupOptionalEnvelope
			if e = json.Unmarshal(omissionRaw, &env); e != nil {
				t.Fatal(e)
			}
			var p backupOptionalOmission
			if e = json.Unmarshal(env.Payload, &p); e != nil {
				t.Fatal(e)
			}
			p.Backup = domain.NewID()
			env.Payload, _ = json.Marshal(p)
			changed, _ := json.Marshal(env)
			if e = os.WriteFile(omission, changed, 0600); e != nil {
				t.Fatal(e)
			}
			for i := range m.Entries {
				for j := range m.Entries[i].Files {
					f := &m.Entries[i].Files[j]
					if f.Name == backupOptionalOmissionName {
						f.Length = domain.U64(len(changed))
						f.SHA = sha256.Sum256(changed)
					}
				}
			}
			if e = verifyBackupFiles(ctx, body, m, true); e == nil {
				t.Fatal("altered signed omission accepted")
			}
			// 元の署名に戻し、archive形式を旧版へ下げる攻撃も拒否する。
			if e = os.WriteFile(omission, omissionRaw, 0600); e != nil {
				t.Fatal(e)
			}
			for i := range m.Entries {
				for j := range m.Entries[i].Files {
					f := &m.Entries[i].Files[j]
					if f.Name == backupOptionalOmissionName {
						f.Length = domain.U64(len(omissionRaw))
						f.SHA = sha256.Sum256(omissionRaw)
					}
				}
			}
			m.Schema = 1
			if online {
				m.Schema = 2
			}
			if e = verifyBackupFiles(ctx, body, m, true); e == nil {
				t.Fatal("omission accepted in old archive format")
			}
			if e = os.Remove(omission); e != nil {
				t.Fatal(e)
			}
			for i := range m.Entries {
				files := m.Entries[i].Files[:0]
				for _, f := range m.Entries[i].Files {
					if f.Name != backupOptionalOmissionName {
						files = append(files, f)
					}
				}
				m.Entries[i].Files = files
			}
			if e = verifyBackupFiles(ctx, body, m, true); e == nil {
				t.Fatal("enabled log history silently omitted without declaration")
			}
		})
	}
}

// TestBackupOptionalSignedBoundaries は健全な署名でも異なる捕捉境界への流用を拒否する。
func TestBackupOptionalSignedBoundaries(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(key)
	site, id := domain.NewID(), domain.NewID()
	at := domain.Time(time.Now().UnixNano())
	state := store.ControlState{Seq: 7}
	m := backupManifest{ID: id, Site: site, ControlCut: []backupCut{{Kind: "site", Owner: site, Sequence: 7}}}
	raw, e := encodeBackupOptionalOmission(id, site, 7, at, key)
	if e != nil {
		t.Fatal(e)
	}
	public := key.Public().(ed25519.PublicKey)
	if e = verifyBackupOptionalPayload(raw, m, state, at, public); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"backup", "site", "seq", "time", "cut", "key"} {
		t.Run(kind, func(t *testing.T) {
			probe := m
			probe.ControlCut = append([]backupCut(nil), m.ControlCut...)
			current := state
			captured := at
			pub := public
			switch kind {
			case "backup":
				probe.ID = domain.NewID()
			case "site":
				probe.Site = domain.NewID()
			case "seq":
				current.Seq++
			case "time":
				captured++
			case "cut":
				probe.ControlCut[0].Sequence++
			case "key":
				pub = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
			}
			if e := verifyBackupOptionalPayload(raw, probe, current, captured, pub); e == nil {
				t.Fatal("foreign signed boundary accepted")
			}
		})
	}
}
