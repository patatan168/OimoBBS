// 満了再送記録の有界回収・起動再生・時計逆行時の非公開拒否を実保存先で確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func seedExpiredAdminReceipt(t *testing.T, r *Repository, created domain.Time, index byte) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	key := domain.Hash{index}
	request := domain.Hash{index, 1}
	accounts, e := r.administrators()
	if e != nil {
		t.Fatal(e)
	}
	var admin domain.ID
	for _, a := range accounts {
		admin = a.ID
		break
	}
	receipt := adminReceipt{ID: domain.NewID(), Admin: admin, Key: key, Request: request, Name: "保存済み", Revision: r.site.State().Seq + 1, Created: created, Expires: created + 86400e9}
	if e = appendControlAt(r.site, created, "receipt_fixture", []store.Mutation{mutation("admin_receipt", key.String(), receipt, nil)}); e != nil {
		t.Fatal(e)
	}
	return "admin_receipt:" + key.String()
}

func TestControlExpiryBoundedRecovery(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	info, e := r.CreateBoard(context.Background(), "expiry", "記録回収")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	old := domain.Time(now.Add(-25 * time.Hour).UnixNano())
	names := []string{}
	for i := byte(1); i <= 3; i++ {
		names = append(names, seedExpiredAdminReceipt(t, r, old, i))
	}
	active := seedExpiredAdminReceipt(t, r, domain.Time(now.UnixNano()), 4)
	b := r.posting[info.ID]
	value, e := b.worker.Submit(context.Background(), func() (any, error) { return b.adminBoard() })
	if e != nil {
		t.Fatal(e)
	}
	receipt := adminBoardReceipt{ID: domain.NewID(), Admin: domain.NewID(), Key: domain.Hash{5}, Request: domain.Hash{6}, Result: value.(AdminBoard), Created: old, Expires: old + 86400e9}
	_, e = b.worker.Submit(context.Background(), func() (any, error) {
		return nil, appendControlAt(b.control, old, "receipt_fixture", []store.Mutation{mutation("admin_receipt", receipt.Key.String(), receipt, nil)})
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.SweepExpiredControl(context.Background(), 1); e == nil {
		t.Fatal("expiry written before format enable")
	}
	if e = r.EnableControlExpiry(context.Background()); e != nil {
		t.Fatal(e)
	}
	report, e := r.SweepExpiredControl(context.Background(), 1)
	if e != nil || report.Site != 1 || report.Boards != 1 || !report.More {
		t.Fatal(report, e)
	}
	if _, ok := r.site.State().Rows[active]; !ok {
		t.Fatal("live receipt removed")
	}
	report, e = r.SweepExpiredControl(context.Background(), 128)
	if e != nil || report.Site != 2 || report.More {
		t.Fatal(report, e)
	}
	for _, name := range names {
		if _, ok := r.site.State().Rows[name]; ok {
			t.Fatal("expired receipt retained")
		}
	}
	before := r.site.State().Seq
	report, e = r.SweepExpiredControl(context.Background(), 128)
	if e != nil || report.Site != 0 || report.Boards != 0 || r.site.State().Seq != before {
		t.Fatal("idle pass wrote WAL", report, e)
	}
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "expiry-candidate")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := r.site.State().Rows[active]; !ok {
		t.Fatal("live receipt lost on restart")
	}
	for _, name := range names {
		if _, ok := r.site.State().Rows[name]; ok {
			t.Fatal("removed receipt revived")
		}
	}
	if r.controlExpiryFloor.Load() == 0 {
		t.Fatal("durable boundary not restored")
	}
	if _, e = inspectSiteState(r.site.State(), siteID(r.site.State()), cfg.Public.BaseURL); e != nil {
		t.Fatal(e)
	}
}

func TestControlExpiryDurableClockRegression(t *testing.T) {
	cfg, r := adminFixture(t)
	seedExpiredAdminReceipt(t, r, domain.Time(time.Now().Add(-25*time.Hour).UnixNano()), 1)
	if e := r.EnableControlExpiry(context.Background()); e != nil {
		t.Fatal(e)
	}
	future := time.Now().Add(time.Hour)
	if _, e := r.sweepExpiredControl(context.Background(), 128, func() time.Time { return future }); e != nil {
		t.Fatal(e)
	}
	if e := r.available(); !errors.Is(e, ErrControlExpiryClock) {
		t.Fatal("regressed process admitted operations", e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if reopened, e := OpenPostingRepository(cfg, postcapture.Validate); e == nil {
		reopened.Close()
		t.Fatal("clock regression reopened cleaned history")
	}
}

func TestControlExpiryRevocationReceiptDependency(t *testing.T) {
	now := domain.Time(time.Now().UnixNano())
	revoked := now - 32*86400e9
	revocation := tokenRevocation{ID: domain.NewID(), Subject: domain.Hash{1}, KeyID: 4, Generation: 1, Revoked: revoked, Expires: revoked + 31*86400e9, Reason: "local_admin"}
	receipt := anonymousReceipt{Type: "anonymous_change", ID: domain.NewID(), Admin: domain.NewID(), Key: domain.Hash{2}, Request: domain.Hash{3}, Result: AdminAnonymous{Enabled: true, Mode: "required", Generation: 1, Revision: 1, Revocations: 1}, Created: now - 1, Expires: now + 86400e9 - 1}
	revocationRaw, _ := json.Marshal(revocation)
	receiptRaw, _ := json.Marshal(receipt)
	state := store.ControlState{Rows: map[string]store.ControlRow{"token_revocation:" + revocation.Subject.String(): {Value: revocationRaw}, "admin_receipt:" + receipt.Key.String(): {Value: receiptRaw}}}
	names, e := expiredControlNames(state, 1, now)
	if e != nil || len(names) != 0 {
		t.Fatal("live receipt dependency discarded", names, e)
	}
	names, e = expiredControlNames(state, 1, now+86400e9)
	if e != nil || len(names) != 2 {
		t.Fatal(names, e)
	}
	// 新しい設定操作が続いても、満了済みの失効行へ新たな件数依存を作らない。
	fresh := receipt
	fresh.Key = domain.Hash{4}
	fresh.Created = now
	fresh.Expires = now + 86400e9
	fresh.Result.Revocations = 0
	raw, _ := json.Marshal(fresh)
	state.Rows["admin_receipt:"+fresh.Key.String()] = store.ControlRow{Value: raw}
	names, e = expiredControlNames(state, 1, now+86400e9-1)
	if e != nil || len(names) != 2 {
		t.Fatal("new receipt prolonged old revocation", names, e)
	}
	if e = validateSiteValue("key_metadata", "1", json.RawMessage(`{}`), json.RawMessage("null")); e == nil {
		t.Fatal("required keys removable")
	}
	if e = validateBoardValue("key_watermark", "thread", json.RawMessage(`{"last_reserved_key":"1"}`), json.RawMessage("null")); e == nil {
		t.Fatal("reservation watermark removable")
	}
	if e = validateControlExpiryWatermark("control", json.RawMessage(fmt.Sprintf(`{"observed_at_ns":"%d"}`, now)), json.RawMessage(fmt.Sprintf(`{"observed_at_ns":"%d"}`, now-1))); e == nil {
		t.Fatal("watermark rolled back")
	}
}

// TestEditedBoardSurvivesReceiptExpiry は編集済み設定を、再送receipt回収後も正本から復旧する。
func TestEditedBoardSurvivesReceiptExpiry(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	info, e := r.CreateBoard(context.Background(), "editedexpiry", "編集記録満了")
	if e != nil {
		t.Fatal(e)
	}
	b := r.posting[info.ID]
	old := domain.Time(time.Now().Add(-25 * time.Hour).UnixNano())
	_, e = b.worker.Submit(context.Background(), func() (any, error) {
		state := b.control.State()
		var board boardValue
		if e := strictjson.Decode(state.Rows["board:state"].Value, &board); e != nil {
			return nil, e
		}
		board.Settings.Version++
		board.Settings.Input.Noname = "保存された名無し"
		receipt := adminBoardReceipt{ID: domain.NewID(), Admin: domain.NewID(), Key: domain.Hash{71}, Request: domain.Hash{72}, Result: AdminBoard{ID: info.ID, Key: info.Key, Name: info.Name, Revision: state.Seq + 1, Settings: boardEdit(board)}, Created: old, Expires: old + 86400e9}
		return nil, appendControlAt(b.control, old, "receipt_fixture", []store.Mutation{mutation("board", "state", board, nil), mutation("admin_receipt", receipt.Key.String(), receipt, nil)})
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = r.EnableControlExpiry(context.Background()); e != nil {
		t.Fatal(e)
	}
	swept, e := r.SweepExpiredControl(context.Background(), 128)
	if e != nil || swept.Boards != 1 {
		t.Fatal(swept, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	verify := func() {
		t.Helper()
		b := r.posting[info.ID]
		value, e := b.worker.Submit(context.Background(), func() (any, error) {
			for key := range b.control.State().Rows {
				if strings.HasPrefix(key, "admin_receipt:") {
					return nil, fmt.Errorf("expired receipt retained")
				}
			}
			return b.adminBoard()
		})
		if e != nil || value.(AdminBoard).Settings.Input.Noname != "保存された名無し" {
			t.Fatal(value, e)
		}
	}
	verify()
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "edited-receipt-expiry")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	verify()
}
