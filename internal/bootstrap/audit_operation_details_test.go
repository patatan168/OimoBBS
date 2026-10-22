// 元ログからの操作種別復元が再起動・絞込み・既存監査証明と両立することを検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func TestAuditSourceOperationDetails(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	actor := domain.NewID()
	request := domain.Hash{1}
	keyID := uint32(1)
	id := domain.NewID()
	state := repo.site.State()
	reason := "board_categories_update"
	frame, err := controlFrame(state, id, domain.Time(time.Now().UnixNano()), reason,
		[]store.Mutation{{Collection: "site", Key: "state", Value: state.Rows["site:state"].Value}},
		[]string{}, domain.Actor{Kind: "admin", ID: &actor, Reason: reason, Request: &request, Idempotency: &request, KeyID: &keyID})
	if err != nil {
		t.Fatal(err)
	}
	if result := repo.site.Append(frame); result.Status != store.Durable {
		t.Fatal(result)
	}
	q := auditQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Action: reason}
	for attempt := 0; attempt < 2; attempt++ {
		rows, err := collectAuditFixture(repo, context.Background(), q)
		if err != nil || len(rows) != 1 || rows[0].ID != id || rows[0].Action != reason {
			t.Fatalf("restored rows: %v %v", rows, err)
		}
		row := newAuditRow(rows[0], nil)
		if !strings.Contains(row.Label, "カテゴリー") || len(row.FieldLabels) != 1 {
			t.Fatal(row)
		}
		// 保存済み正本を表示の都合で書き換えず、連続性検査を維持する。
		_, entries, err := repo.loadAuditProof(context.Background(), rows[0].Owner, "site", newArchiveBudget())
		if err != nil || entries[id].Summary.Action != "other_admin_operation" {
			t.Fatal("canonical summary changed", err)
		}
		if report, err := repo.VerifyAuditTransfer(context.Background()); err != nil || !report.Complete {
			t.Fatal(report, err)
		}
		if attempt == 0 {
			if err := repo.Close(); err != nil {
				t.Fatal(err)
			}
			repo, err = OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func newArchiveBudget() *int64 { value := int64(64 << 20); return &value }

func TestAuditSourceOperationAllowlist(t *testing.T) {
	for action, fields := range auditSourceActions {
		if auditLabels[action] == "" || auditDescriptions[action] == "" {
			t.Fatal("missing presentation", action)
		}
		for _, field := range fields {
			if auditFieldLabels[field] == "" {
				t.Fatal("missing field", field)
			}
		}
	}
	entry := AuditEntry{Owner: domain.NewID(), ID: domain.NewID(), Action: "other_admin_operation", Fields: []string{}}
	before, _ := json.Marshal(entry)
	index := auditIndex{}
	index.rememberOperation(entry, "PRIVATE_PASSWORD_AND_REASON")
	if len(index.details) != 0 {
		t.Fatal("unapproved reason retained")
	}
	index.rememberOperation(entry, "administrator_passkey_remove")
	if got := index.describeEntry(entry); got.Action != "administrator_passkey_remove" {
		t.Fatal(got)
	}
	after, _ := json.Marshal(entry)
	if string(before) != string(after) {
		t.Fatal("source mutated")
	}
	other := entry
	other.Owner = domain.NewID()
	if index.describeEntry(other).Action != entry.Action {
		t.Fatal("cross-owner classification")
	}
}
