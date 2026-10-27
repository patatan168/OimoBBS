// 製品reader45の原本回収済み起動と、低readerの非変更拒否を実Repositoryで検査する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRequiredOriginalProductStartupReader45(t *testing.T) {
	for _, minimum := range []uint32{44, 45} {
		for _, stage := range []string{"", "required:removed", "required:snapshot_intent", "required:snapshot_current"} {
			t.Run(fmt.Sprintf("reader%d/%s", minimum, stage), func(t *testing.T) {
				testRequiredOriginalProductStartup(t, minimum, stage, false)
			})
		}
	}
	t.Run("future_floor", func(t *testing.T) {
		testRequiredOriginalProductStartup(t, 45, "required:snapshot_current", true)
	})
}

func testRequiredOriginalProductStartup(t *testing.T, minimum uint32, stage string, future bool) {
	t.Helper()
	ctx := context.Background()
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "原本回収起動"); e != nil {
		t.Fatal(e)
	}
	r, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if r != nil {
			_ = r.Close()
		}
	}()
	if _, e = r.ConfigureAdministrator("owner", "所有者", adminTestSecret, false); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	info, e := r.CreateBoard(ctx, "retired", "回収済み")
	if e != nil {
		t.Fatal(e)
	}
	if e = r.EnablePublicBodyReclamation(ctx); e != nil {
		t.Fatal(e)
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	site.MinimumReader = minimum
	if e = appendControl(r.site, "required_reader_test", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	frame, _, e := store.ReadFrame(bytes.NewReader(persistentFrame(t)))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(frame.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	var create domain.Create
	if e = json.Unmarshal(op.Payload, &create); e != nil {
		t.Fatal(e)
	}
	at := domain.Time(time.Now().AddDate(-1, 0, 0).UnixNano())
	op.Committed, op.After.LastUserAt, op.Dedup.Expires = at, at, at+86400e9
	create.Created, create.Posts[0].Created, create.Expires = at, at, domain.Time(domain.SixMonths(time.Unix(0, int64(at))).UnixNano())
	op.Payload, _ = json.Marshal(create)
	frame.Records[0].JSON, _ = json.Marshal(op)
	raw, e := store.EncodeFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	b := r.posting[info.ID]
	value, e := b.worker.Submit(ctx, func() (any, error) {
		b.clock = func() time.Time { return time.Unix(0, int64(at)) }
		defer func() { b.clock = time.Now }()
		return b.post(0, raw, []byte(`{"fixture":true}`)), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	result := value.(RepositoryPostingResult)
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	stop := errors.New("required source interrupted")
	_, e = b.worker.Submit(ctx, func() (any, error) {
		if _, e := b.scanExpiry(true); e != nil {
			return nil, e
		}
		if e := b.cleanPublicBodies(8); e != nil {
			return nil, e
		}
		if !b.threads[result.ThreadKey].Reclaimed() {
			return nil, errors.New("public body not collected")
		}
		for _, j := range b.journals {
			entries := j.Entries()
			if len(entries) < 2 {
				continue
			}
			i, e := app.PostingRetirementIdentity(entries[0], entries[1])
			if e != nil {
				return nil, e
			}
			floor := create.Expires
			if future {
				floor = domain.Time(time.Now().Add(24 * time.Hour).UnixNano())
			}
			_, e = j.PruneRequired(floor, func(evidence.Entry) (*evidence.RequiredPostingIdentity, error) { return &i, nil }, func(domain.ID, domain.Time) (bool, error) { return false, nil }, func(at string) error {
				if stage != "" && at == stage {
					return stop
				}
				return nil
			})
			if e != nil {
				return nil, e
			}
		}
		return nil, nil
	})
	if stage == "" && e != nil || stage != "" && !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, b.evidenceDir)
	_, e = checkLockedPosting(cfg, false, true)
	if minimum < 45 || future {
		assertRequiredStartupRefusal(t, e, future)
		opened, err := OpenPostingRepository(cfg, postingCaptureFixture)
		if opened != nil {
			_ = opened.Close()
			t.Fatal("unsupported source opened")
		}
		assertRequiredStartupRefusal(t, err, future)
		if !reflect.DeepEqual(before, requiredStartupFiles(t, b.evidenceDir)) {
			t.Fatal("startup refusal changed original source")
		}
		return
	}
	if e != nil {
		t.Fatal("read-only product check", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, b.evidenceDir)) {
		t.Fatal("read-only check changed original source")
	}
	r, e = OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal("reader45 startup", e)
	}
	if !r.posting[info.ID].threads[result.ThreadKey].Reclaimed() {
		t.Fatal("required original resurrected")
	}
	rows, e := r.rateHistory()
	if e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
	assertCarrySourceSnapshot(t, filepath.Join(cfg.DataDir, "expiry", info.ID.String(), fmt.Sprint(result.ThreadKey)), info.ID, result.ThreadKey)
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
}

func assertRequiredStartupRefusal(t *testing.T, err error, future bool) {
	t.Helper()
	if future {
		if !errors.Is(err, evidence.ErrRetirementClock) {
			t.Fatal("clock refusal", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "required retirement exceeds site minimum reader") {
		t.Fatal("reader refusal", err)
	}
}

func requiredStartupFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	if e := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		files[path] = raw
		return err
	}); e != nil {
		t.Fatal(e)
	}
	return files
}
