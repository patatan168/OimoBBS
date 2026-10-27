// 実fileから復旧した回収履歴だけを満了扱いし、規制復旧で原文の捏造をしないことを検査する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func retiredAdmissionFixture(t *testing.T) (*Repository, boardRateRecord) {
	t.Helper()
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
	committed := time.Now().AddDate(-1, 0, 0)
	at := domain.Time(committed.UnixNano())
	op.Committed, op.After.LastUserAt, op.Dedup.Expires = at, at, at+86400e9
	create.Created, create.Expires, create.Posts[0].Created = at, domain.Time(domain.SixMonths(committed).UnixNano()), at
	op.Payload, _ = json.Marshal(create)
	frame.Records[0].JSON, _ = json.Marshal(op)
	raw, e := store.EncodeFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	owner := domain.NewID()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	parent := filepath.Join(root, "threads")
	if e = os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	// source日はfixtureの時刻からJSTの八桁キーを求める。
	var sourceDay uint64
	for _, c := range committed.In(domain.JST).Format("20060102") {
		sourceDay = sourceDay*10 + uint64(c-'0')
	}
	path := filepath.Join(root, "evidence")
	j, e := evidence.OpenJournal(path, owner, sourceDay, 10, key, app.PostingValidator(postingCaptureFixture))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	p, e := app.OpenPosting(parent, owner, 1, []*evidence.Journal{j}, j, at)
	if e != nil {
		t.Fatal(e)
	}
	if result := p.Post(context.Background(), raw, []byte(`{"fixture":true}`), at); result.Status != store.Durable {
		t.Fatal(result)
	}
	entries := j.Entries()
	identity, e := app.PostingRetirementIdentity(entries[0], entries[1])
	if e != nil {
		t.Fatal(e)
	}
	proof, e := p.PrepareBodyReclamation(context.Background(), domain.NewID(), "expire", create.Expires, key)
	if e != nil {
		t.Fatal(e)
	}
	carry, e := p.ExportBodyCarry(proof.Floor, proof.CarryAt())
	if e != nil {
		t.Fatal(e)
	}
	if e = p.RetireBody(proof); e != nil {
		t.Fatal(e)
	}
	if e = store.RemoveReclaimedBody(context.Background(), filepath.Join(parent, "1"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	p.Close()
	if n, e := j.PruneRequired(create.Expires, func(evidence.Entry) (*evidence.RequiredPostingIdentity, error) { return &identity, nil }, func(domain.ID, domain.Time) (bool, error) { return false, nil }, nil); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j, e = evidence.OpenJournal(path, owner, sourceDay, 10, key, app.PostingValidator(postingCaptureFixture))
	if e != nil {
		t.Fatal(e)
	}
	p, e = app.OpenPostingWithRetiredOriginals(parent, owner, 1, []*evidence.Journal{j}, j, domain.Time(time.Now().UnixNano()), proof, &carry, key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { p.Close() })
	w := board.NewWorker()
	t.Cleanup(w.Close)
	r := &Repository{posting: map[domain.ID]*postingBoard{owner: {worker: w, threads: map[uint64]*app.PostingLog{1: p}, control: &store.ControlLog{}}}, admission: &admission{policy: initialAdmission(committed.Add(time.Hour)), limits: abuse.NewLimiter(100)}}
	rows, e := r.rateHistory()
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	return r, rows[0]
}

func TestRetiredAdmissionHistoryRequiresVerifiedProof(t *testing.T) {
	r, row := retiredAdmissionFixture(t)
	if skip, e := retiredRateHistoryRow(row, domain.Time(time.Now().UnixNano())); e != nil || !skip {
		t.Fatal(skip, e)
	}
	if e := r.restoreAdmission(); e != nil {
		t.Fatal("verified expired history prevented admission recovery", e)
	}
	if r.admission.lastReserved != 0 {
		t.Fatal("expired quota was charged")
	}
	for _, change := range []string{"schema_only", "owner", "key", "operation", "ip"} {
		t.Run(change, func(t *testing.T) {
			v := row
			switch change {
			case "schema_only":
				v.record.Retirement = nil
			case "owner":
				v.owner = domain.NewID()
			case "key":
				v.key++
			case "operation":
				v.record.ID = domain.NewID()
			case "ip":
				v.record.IP = "192.0.2.10"
			}
			if skip, e := retiredRateHistoryRow(v, domain.Time(time.Now().UnixNano())); !errors.Is(e, app.ErrEvidenceGap) || skip {
				t.Fatal("unproven history skipped", skip, e)
			}
		})
	}
	if skip, e := retiredRateHistoryRow(row, row.record.At); !errors.Is(e, evidence.ErrRetirementClock) || skip {
		t.Fatal("clock rollback skipped validation", skip, e)
	}
	normal := boardRateRecord{owner: row.owner, key: row.key, record: app.RateRecord{Schema: "form-post-v1", At: row.record.At, IP: "192.0.2.1"}}
	if skip, e := retiredRateHistoryRow(normal, domain.Time(time.Now().UnixNano())); e != nil || skip {
		t.Fatal("normal history validation bypassed", skip, e)
	}
}
