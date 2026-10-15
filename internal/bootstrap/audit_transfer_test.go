// 移管証明の照合、追記による未移管判定、欠落・内容不一致の拒否を確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditTransferProofAndMissingArchive(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	report, e := r.VerifyAuditTransfer(context.Background())
	if e != nil || report.Complete {
		t.Fatal("proof before import", report, e)
	}
	q := auditQuery{From: time.Now().Add(-24 * time.Hour), To: time.Now().Add(time.Second), Limit: 200}
	rows, e := collectAuditFixture(r, context.Background(), q)
	if e != nil {
		t.Fatal(e)
	}
	report, e = r.VerifyAuditTransfer(context.Background())
	if e != nil || !report.Complete || len(report.Owners) != 1 || report.Owners[0].Entries != domain.U64(len(rows)) {
		t.Fatal(report, e)
	}
	// sourceだけ進んだ場合、過去の証明は有効でも最新seqまで移管済みとは報告しない。
	func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if e = appendControl(r.site, "anonymous_issue", []store.Mutation{mutation("site", "state", json.RawMessage(r.site.State().Rows["site:state"].Value), nil)}, []string{}); e != nil {
			t.Fatal(e)
		}
	}()
	report, e = r.VerifyAuditTransfer(context.Background())
	if e != nil || report.Complete {
		t.Fatal("stale proof", report, e)
	}
	if _, e = collectAuditFixture(r, context.Background(), q); e != nil {
		t.Fatal(e)
	}
	r.Close()
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	// 再起動直後でも、再取込みなしに証明と正本を照合できる。
	report, e = r.VerifyAuditTransfer(context.Background())
	if e != nil || !report.Complete {
		t.Fatal("reopened", report, e)
	}
	// CRC等が正しい監査ファイルでも、要約を一つ失っていれば照合を失敗させる。
	row := rows[0]
	at, _ := time.Parse(time.RFC3339Nano, row.Committed)
	dir := filepath.Join(cfg.DataDir, "audit", row.Owner.String(), at.UTC().Format("20060102"))
	log, e := store.OpenControl(dir, 4, row.Owner, uint64(mustAuditDate(t, at)), auditValueValidator(row.Owner, row.OwnerKind, at.UTC().Format("20060102")))
	if e != nil {
		t.Fatal(e)
	}
	proof := append([]byte{}, log.State().Rows["import_receipt:source"].Value...)
	log.Close()
	if e = os.RemoveAll(dir); e != nil {
		t.Fatal(e)
	} // 試験専用の一時データだけを置換する。
	h, first, e := auditInitial(row.Owner, row.OwnerKind, at.UTC().Format("20060102"))
	if e != nil {
		t.Fatal(e)
	}
	log, e = store.CreateControl(dir, h, first, auditValueValidator(row.Owner, row.OwnerKind, at.UTC().Format("20060102")))
	if e != nil {
		t.Fatal(e)
	}
	if len(proof) > 0 {
		if e = appendControl(log, "audit_transfer", []store.Mutation{mutation("import_receipt", "source", json.RawMessage(proof), nil)}, []string{}); e != nil {
			t.Fatal(e)
		}
	}
	log.Close()
	if _, e = r.VerifyAuditTransfer(context.Background()); e == nil {
		t.Fatal("missing archive accepted")
	}
	// 型・CRCは正しくても、sourceと内容が違う保存要約を受け入れない。
	row.Action = "site_name_update"
	row.Fields = []string{"site.name"}
	sink := auditSink{root: filepath.Join(cfg.DataDir, "audit")}
	if e = sink.put(row); e != nil {
		t.Fatal(e)
	}
	if e = sink.close(); e != nil {
		t.Fatal(e)
	}
	if _, e = r.VerifyAuditTransfer(context.Background()); e == nil {
		t.Fatal("changed summary accepted")
	}

}

func TestAuditTransferBoardAndBounds(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, e := r.CreateBoard(context.Background(), "audit_board", "移管確認")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.ReserveThreadKey(context.Background(), board.ID, time.Now()); e != nil {
		t.Fatal(e)
	}
	budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	if e = catchUpAuditFixture(r, context.Background(), &budget); e != nil {
		t.Fatal(e)
	}
	report, e := r.VerifyAuditTransfer(context.Background())
	if e != nil || !report.Complete || len(report.Owners) != 2 {
		t.Fatal(report, e)
	}
	found := false
	for _, owner := range report.Owners {
		if owner.Owner == board.ID {
			found = true
			if owner.Kind != "board" || !owner.Complete || owner.VerifiedSeq == 0 {
				t.Fatal(owner)
			}
		}
	}
	if !found {
		t.Fatal("board proof missing")
	}
	// 上限・取消で一部の証明だけを成功として返さない。
	tiny := int64(1)
	if _, _, e = r.loadAuditProof(context.Background(), board.ID, "board", &tiny); e != store.ErrHistoryBudget {
		t.Fatal("archive budget", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = r.VerifyAuditTransfer(ctx); e != context.Canceled {
		t.Fatal(e)
	}
}

func TestAuditTransferValueRejectsRegression(t *testing.T) {
	now := time.Now().UTC()
	owner := domain.NewID()
	p := auditTransfer{Schema: 1, Kind: "source_transfer", Owner: owner, OwnerKind: "site", Generation: 1, Sequence: 10, SourceHash: domain.Hash{1}, Entries: 2, SummaryHash: domain.Hash{2}, Since: domain.Time(now.Add(-auditRetention).UnixNano()), Imported: domain.Time(now.UnixNano())}
	raw, _ := json.Marshal(p)
	day := now.Format("20060102")
	if e := validateAuditTransfer(owner, "site", day, nil, raw); e != nil {
		t.Fatal(e)
	}
	cases := []func(*auditTransfer){
		func(p *auditTransfer) { p.Sequence-- },
		func(p *auditTransfer) { p.SourceHash = domain.Hash{3} },
		func(p *auditTransfer) { p.SummaryHash = domain.Hash{3} },
		func(p *auditTransfer) { p.Entries-- },
		func(p *auditTransfer) { p.Since++ },
		func(p *auditTransfer) { p.Since-- },
		func(p *auditTransfer) { p.Owner = domain.NewID() },
		func(p *auditTransfer) { p.Generation++ },
	}
	for i, change := range cases {
		next := p
		change(&next)
		value, _ := json.Marshal(next)
		if e := validateAuditTransfer(owner, "site", day, raw, value); e == nil {
			t.Fatal("invalid proof", i)
		}
	}
}
