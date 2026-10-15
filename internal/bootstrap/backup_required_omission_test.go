// 実必須予約のある通常backupを署名除外し、元保存先なしの隔離再生と製品起動拒否を確認する。
package bootstrap

import (
	"context"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupRequiredOmissionRoundTrip(t *testing.T) {
	for _, online := range []bool{false, true} {
		for _, optional := range []bool{false, true} {
			name := map[bool]string{false: "offline", true: "online"}[online] + map[bool]string{false: "_required", true: "_both"}[optional]
			t.Run(name, func(t *testing.T) {
				cfg, r, id := requiredHoldStorageFixture(t)
				_, _, _ = productRequiredReservation(t, r, id)
				if optional {
					s := optionalProductServer(t, r)
					res, e := s.Client().Get(s.URL + "/")
					if e != nil {
						t.Fatal(e)
					}
					res.Body.Close()
					s.Close()
				}
				reportSite := siteID(r.site.State())
				body, keys, work := onlineOutput(t, "body"), onlineOutput(t, "keys"), filepath.Dir(onlineOutput(t, "work-unused"))
				ctx := context.Background()
				var report BackupReport
				var e error
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
						t.Fatal("online capture", e)
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
						t.Fatal("offline capture", e)
					}
				}
				if !report.Verified || !report.RequiredOriginalHoldsOmitted || report.OptionalHTTPLogsOmitted != optional || report.RestoreReady {
					t.Fatal(report)
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
					probe := cfg
					probe.DataDir = root
					before := requiredStartupFiles(t, root)
					state, e := inspectRuntimeControl(root, "site", reportSite)
					if e != nil {
						return e
					}
					var site siteState
					if e = strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil {
						return e
					}
					if e = inspectRequiredHoldStorage(probe, site, state, true); e == nil || !strings.Contains(e.Error(), "excluded required-original") {
						t.Fatal("product startup guard accepted or hid missing history", e)
					}
					assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, root))
					return nil
				})
				if e != nil || !checked || !replay.Replayed || !replay.RequiredOriginalHoldsOmitted || replay.OptionalHTTPLogsOmitted != optional || replay.RestoreReady {
					t.Fatal("isolated replay", replay, e)
				}
				entries, e := os.ReadDir(work)
				if e != nil || len(entries) != 0 {
					t.Fatal("replay cleanup incomplete", e)
				}
			})
		}
	}
}

func TestBackupRequiredOmissionRejectsPreparing(t *testing.T) {
	cfg, r, id := requiredHoldStorageFixture(t)
	r.mu.Lock()
	b, a, e := r.prepareRequiredHoldStorageLocked(context.Background(), id)
	r.mu.Unlock()
	_ = b
	_ = a
	if e != nil {
		t.Fatal(e)
	}
	if _, e = backupRequiredBoards(r.site.State(), siteID(r.site.State())); e == nil {
		t.Fatal("unfinished activation was captured")
	}
	_ = cfg
}
