// 元WALなしのsnapshot復旧と、更新専用規則を緩めないことを検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// TestSnapshotAssignedBoardCategory は有効な現存カテゴリーを保持し、不正参照と作成時指定を拒否する。
func TestSnapshotAssignedBoardCategory(t *testing.T) {
	id, categoryID := domain.NewID(), domain.NewID()
	v := boardDirectory{Key: "categoryboard", Aliases: []string{}, CategoryID: &categoryID, Status: "active", JobID: domain.NewID()}
	raw, _ := json.Marshal(v)
	if err := snapshotSiteValue("board_directory", id.String(), nil, raw); err != nil {
		t.Fatal(err)
	}
	if validateDirectory(id.String(), nil, raw) == nil {
		t.Fatal("snapshot relaxed initial creation")
	}
	zero := domain.ID{}
	v.CategoryID = &zero
	raw, _ = json.Marshal(v)
	if snapshotSiteValue("board_directory", id.String(), nil, raw) == nil {
		t.Fatal("zero category accepted")
	}
	v.CategoryID = &categoryID
	v.Status = "provisioning"
	raw, _ = json.Marshal(v)
	if snapshotSiteValue("board_directory", id.String(), nil, raw) == nil {
		t.Fatal("provisioning category accepted")
	}
}

func TestSnapshotStateIndependentRecovery(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	board, err := r.CreateBoard(context.Background(), "snaptest", "復旧試験")
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, v := client.board(board.ID.String())
	edit := v.Settings
	edit.Input.Noname = "復旧した名無し"
	flag := true
	edit.Hidden, edit.NoReprint = &flag, &flag
	off := false
	edit.AutoReportsEnabled = &off
	raw, _ := json.Marshal(edit)
	res, body := client.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(raw), candidateHeaders(res.Header.Get("ETag"), res.Header.Get("X-CSRF-Token")))
	if res.StatusCode != http.StatusOK {
		t.Fatal(body)
	}
	log := r.boards[board.ID]
	if err = appendControl(log, "reserve_thread_key", []store.Mutation{mutation("key_watermark", "thread", map[string]domain.U64{"last_reserved_key": 123}, nil)}, []string{}); err != nil {
		t.Fatal(err)
	}
	// 解除済み規制も初期作成の遷移を経ずに現在値として復旧できる。
	rule := denialRule{ID: domain.NewID(), Revision: 1, Scope: denialScope{Kind: "board", Board: board.ID}, Operations: []string{"reply"}, Conditions: []denialCondition{{Field: "ip", Operator: "exact", Value: "192.0.2.1", Unknown: "deny"}}, Effect: denialEffect{Type: "deny"}, Starts: 1, Expires: 60000000001, Reason: "manual", Enabled: true}
	if err = appendControl(log, "create_rule", []store.Mutation{mutation("board_rule", rule.ID.String(), rule, nil)}, []string{}); err != nil {
		t.Fatal(err)
	}
	rule.Enabled = false
	rule.Revision = 2
	if err = appendControl(log, "revoke_rule", []store.Mutation{mutation("board_rule", rule.ID.String(), rule, nil)}, []string{}); err != nil {
		t.Fatal(err)
	}
	revoked, _ := json.Marshal(rule)
	if validateBoardValue("board_rule", rule.ID.String(), nil, revoked) == nil {
		t.Fatal("revoked rule accepted as initial creation")
	}
	for _, kind := range []string{"site", "board"} {
		t.Run(kind, func(t *testing.T) {
			source := r.site
			dir := filepath.Join(cfg.DataDir, "site")
			apply := store.ValueValidator(validateSiteValue)
			if kind == "board" {
				source = log
				dir = filepath.Join(cfg.DataDir, "boards", board.ID.String(), "control")
				apply = validateBoardValue
			}
			h := source.HistoryHeader()
			next := h
			next.Generation++
			next.BaseSeq = uint64(source.State().Seq)
			snapshot, err := store.EncodeControlSnapshot(next, source.State(), 6, snapshotValues(kind))
			if err != nil {
				t.Fatal(err)
			}
			// 独立したディレクトリを使い、稼働元には変更を加えない。
			copyDir := candidateParent(t)
			for _, name := range []string{"control.current", "control-000001.wal"} {
				b, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(copyDir, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			copied, err := store.OpenControlWithValidators(copyDir, h.Kind, h.Owner, 0, apply, snapshotValues(kind))
			if err != nil {
				t.Fatal(err)
			}
			if result := copied.SwitchSnapshot(snapshot); result.Status != store.Durable {
				copied.Close()
				t.Fatal(result)
			}
			copied.Close()
			if err = os.Remove(filepath.Join(copyDir, "control-000001.wal")); err != nil {
				t.Fatal(err)
			}
			restored, err := store.InspectControlWithValidators(copyDir, h.Kind, h.Owner, 0, apply, snapshotValues(kind))
			if err != nil || !reflect.DeepEqual(restored, source.State()) {
				t.Fatal("independent recovery", err)
			}
			if err = r.inspectSnapshotState(AuditTransferOwner{Owner: h.Owner, Kind: kind}, restored); err != nil {
				t.Fatal(err)
			}
			// 現在値の検証後も必須行・期限の整合性を省略しない。
			broken := store.ControlState{Seq: restored.Seq, Rows: map[string]store.ControlRow{}}
			for key, row := range restored.Rows {
				broken.Rows[key] = row
			}
			required := "key_metadata:1"
			if kind == "board" {
				required = "bump_watermark:ranking"
			}
			delete(broken.Rows, required)
			if r.inspectSnapshotState(AuditTransferOwner{Owner: h.Owner, Kind: kind}, broken) == nil {
				t.Fatal("missing required row")
			}
			broken.Rows[required] = restored.Rows[required]
			row := broken.Rows[required]
			expiry := domain.Time(1)
			row.Expires = &expiry
			broken.Rows[required] = row
			if r.inspectSnapshotState(AuditTransferOwner{Owner: h.Owner, Kind: kind}, broken) == nil {
				t.Fatal("unexpected expiry")
			}
			reopened, err := store.OpenControlWithValidators(copyDir, h.Kind, h.Owner, 0, apply, snapshotValues(kind))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if kind == "board" {
				// 同じ高水位の再書込みはsnapshot検証では有効でも、更新では拒否する。
				muts := []store.Mutation{mutation("key_watermark", "thread", map[string]domain.U64{"last_reserved_key": 123}, nil)}
				if err = appendControl(reopened, "reserve_thread_key", muts, []string{}); err == nil {
					t.Fatal("transition validation bypassed")
				}
				muts[0] = mutation("key_watermark", "thread", map[string]domain.U64{"last_reserved_key": 124}, nil)
				if err = appendControl(reopened, "reserve_thread_key", muts, []string{}); err != nil {
					t.Fatal(err)
				}
				replayed, err := store.InspectControlWithValidators(copyDir, h.Kind, h.Owner, 0, apply, snapshotValues(kind))
				if err != nil || replayed.Seq != restored.Seq+1 {
					t.Fatal("delta replay", err)
				}
			}
		})
	}
}

func TestSnapshotBoardRejectsUnsupportedState(t *testing.T) {
	initial := boardValue{Name: "板", Status: "open", Settings: defaultBoardSettings()}
	for _, change := range []func(*boardValue){
		func(v *boardValue) { v.Settings.Version = 0 },
		func(v *boardValue) { v.Settings.Input.Noname = "初期値のすり替え" },
		func(v *boardValue) { v.Settings.Presentation.Hidden = new(false) },
		func(v *boardValue) { v.Settings.Presentation.NoReprint = new(false) },
		func(v *boardValue) { v.Settings.Version = 2; v.Settings.Identity.IDMode = "none" },
		func(v *boardValue) { v.Settings.Version = 2; v.Settings.Input.BodyBytes = 0 },
		func(v *boardValue) { v.Settings.Version = 2; v.Settings.Presentation.TopThreads++ },
	} {
		v := initial
		change(&v)
		raw, _ := json.Marshal(v)
		if snapshotBoardValue("board", "state", nil, raw) == nil {
			t.Fatal("invalid state accepted")
		}
	}
	if snapshotBoardValue("key_watermark", "thread", nil, json.RawMessage(`{"last_reserved_key":"123","unknown":1}`)) == nil {
		t.Fatal("unknown field")
	}
	raw, _ := json.Marshal(initial)
	if snapshotBoardValue("board", "state", raw, raw) == nil {
		t.Fatal("snapshot validator used as mutation validator")
	}
}

func TestSnapshotBoardPresentationFlags(t *testing.T) {
	for _, hidden := range []*bool{nil, new(false), new(true)} {
		for _, noReprint := range []*bool{nil, new(false), new(true)} {
			v := boardValue{Name: "板", Status: "open", Settings: defaultBoardSettings()}
			v.Settings.Version = 2
			v.Settings.Presentation.Hidden = hidden
			v.Settings.Presentation.NoReprint = noReprint
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if err = snapshotBoardValue("board", "state", nil, raw); err != nil {
				t.Fatalf("valid presentation flags hidden=%v no_reprint=%v: %v", hidden, noReprint, err)
			}
		}
	}
}
