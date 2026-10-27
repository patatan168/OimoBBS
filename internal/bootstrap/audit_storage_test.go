// 日別要約の再送・期限固定・保存途中の再起動と、索引の差分更新を確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestAuditDailyArchiveAndResume(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	q := auditQuery{From: time.Now().Add(-24 * time.Hour), To: time.Now().Add(time.Second), Limit: 200}
	rows, e := collectAuditFixture(r, context.Background(), q)
	if e != nil || len(rows) == 0 {
		t.Fatal(rows, e)
	}
	first := rows[0]
	at, _ := time.Parse(time.RFC3339Nano, first.Committed)
	dir := filepath.Join(cfg.DataDir, "audit", first.Owner.String(), at.UTC().Format("20060102"))
	before, e := os.ReadFile(filepath.Join(dir, "control-000001.wal"))
	if e != nil {
		t.Fatal(e)
	}
	// 追いついた索引からの取得はsource frameを消費しない。
	if e = catchUpAuditFixture(r, context.Background(), &store.HistoryBudget{}); e != nil {
		t.Fatal(e)
	}
	again, e := collectAuditFixture(r, context.Background(), q)
	if e != nil || len(again) != len(rows) {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "control-000001.wal"))
	if string(before) != string(after) {
		t.Fatal("duplicate import")
	}
	r.Close()
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	again, e = collectAuditFixture(r, context.Background(), q)
	if e != nil || len(again) != len(rows) {
		t.Fatal(e)
	}
	after, _ = os.ReadFile(filepath.Join(dir, "control-000001.wal"))
	if string(before) != string(after) {
		t.Fatal("restart duplicated import")
	}
	state, e := store.InspectControl(dir, 4, first.Owner, uint64(mustAuditDate(t, at)), auditValueValidator(first.Owner, first.OwnerKind, at.UTC().Format("20060102")))
	if e != nil {
		t.Fatal(e)
	}
	var saved auditStoredEntry
	if e = json.Unmarshal(state.Rows["audit_entry:"+first.ID.String()].Value, &saved); e != nil {
		t.Fatal(e)
	}
	if saved.Expires != domain.Time(at.Add(auditRetention).UnixNano()) {
		t.Fatal("expiry was extended")
	}
	// 同じIDで内容が変わった要約は既存保存を上書きしない。
	first.Sequence++
	sink := auditSink{root: filepath.Join(cfg.DataDir, "audit")}
	defer sink.close()
	if e = sink.put(first); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("conflicting import", e)
	}
}
func mustAuditDate(t *testing.T, at time.Time) int {
	t.Helper()
	return at.Year()*10000 + int(at.Month())*100 + at.Day()
}

func TestAuditImportFailureAndBudgetResume(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 1}
	if e := catchUpAuditFixture(r, context.Background(), &budget); !errors.Is(e, store.ErrHistoryBudget) {
		t.Fatal("budget", e)
	}
	// 保存後・索引更新前の中断を模擬する。再実行で同じ日別行を再利用する。
	r.checkpoint = func(stage string) {
		if stage == "audit:durable" {
			panic("interrupted")
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("checkpoint not reached")
			}
		}()
		budget = store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
		_ = catchUpAuditFixture(r, context.Background(), &budget)
	}()
	r.checkpoint = func(string) {}
	budget = store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	if e := catchUpAuditFixture(r, context.Background(), &budget); e != nil {
		t.Fatal(e)
	}
	if r.auditIndex.count != 1 {
		t.Fatal("lost or duplicated", r.auditIndex.count)
	}
	budget = store.HistoryBudget{}
	if e := catchUpAuditFixture(r, context.Background(), &budget); e != nil {
		t.Fatal(e)
	}
}

func TestAuditPartialCreationAndCorruption(t *testing.T) {
	owner := domain.NewID()
	now := time.Now().UTC()
	entry := AuditEntry{ID: domain.NewID(), Owner: owner, OwnerKind: "site", Sequence: 1, Committed: now.Format(time.RFC3339Nano), ActorKind: "system", Action: "site_name_update", Targets: []string{}, Fields: []string{"site.name"}}
	for _, partial := range []int{0, 30, 100} {
		t.Run(strconv.Itoa(partial), func(t *testing.T) {
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal(e)
			}
			ownerDir := filepath.Join(root, owner.String())
			if e := os.Mkdir(ownerDir, 0700); e != nil {
				t.Fatal(e)
			}
			day := now.Format("20060102")
			dir := filepath.Join(ownerDir, day)
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			h, frame, e := auditInitial(owner, "site", day)
			if e != nil {
				t.Fatal(e)
			}
			header, _ := store.EncodeHeader(h)
			block, e := store.EncodeWALBlock([][]byte{frame})
			if e != nil {
				t.Fatal(e)
			}
			initial := append(header, block...)
			if partial > 0 {
				if e = os.WriteFile(filepath.Join(dir, "control-000001.wal"), initial[:partial], 0600); e != nil {
					t.Fatal(e)
				}
			}
			sink := auditSink{root: root}
			if e = sink.put(entry); e != nil {
				t.Fatal("resume", e)
			}
			if e = sink.close(); e != nil {
				t.Fatal(e)
			}
			// 初期必須prefixの破損は修復で上書きしない。
			path := filepath.Join(dir, "control-000001.wal")
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			raw[70] ^= 1
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if e = sink.put(entry); !errors.Is(e, store.ErrCorrupt) {
				t.Fatal("corruption accepted", e)
			}
			after, _ := os.ReadFile(path)
			if string(raw) != string(after) {
				t.Fatal("corruption overwritten")
			}
		})
	}
}

func TestAuditStorageFailureDoesNotSkipSource(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	root := filepath.Join(cfg.DataDir, "audit")
	if e := os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	if e := catchUpAuditFixture(r, context.Background(), &budget); e == nil {
		t.Fatal("insecure sink accepted")
	}
	if r.auditIndex.count != 0 {
		t.Fatal("unpersisted entry indexed")
	}
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	budget = store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	if e := catchUpAuditFixture(r, context.Background(), &budget); e != nil {
		t.Fatal(e)
	}
	if r.auditIndex.count != 1 {
		t.Fatal("source skipped", r.auditIndex.count)
	}
}
