// 実製品の起動時に未受理を確定し、24時間回収とreader先行保存を再起動まで確認する。
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func agedRejectedFrame(t *testing.T) ([]byte, domain.Time) {
	t.Helper()
	f, _, e := store.ReadFrame(bytes.NewReader(persistentFrame(t)))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	var create domain.Create
	if e = json.Unmarshal(op.Payload, &create); e != nil {
		t.Fatal(e)
	}
	at := domain.Time(time.Now().Add(-25 * time.Hour).UnixNano())
	op.Committed, op.After.LastUserAt, op.Dedup.Expires = at, at, at+domain.Time(24*time.Hour)
	create.Created, create.Posts[0].Created = at, at
	create.Expires = domain.Time(domain.SixMonths(time.Unix(0, int64(at))).UnixNano())
	op.Payload, _ = json.Marshal(create)
	f.Records[0].JSON, _ = json.Marshal(op)
	raw, e := store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	return raw, at
}

func appendRejectedProposal(t *testing.T, r *Repository, id domain.ID, key uint64, raw []byte, at domain.Time) {
	t.Helper()
	b := r.posting[id]
	_, e := b.worker.Submit(t.Context(), func() (any, error) {
		j, e := b.journal(time.Unix(0, int64(at)))
		if e != nil {
			return nil, e
		}
		f, _, e := store.ReadFrame(bytes.NewReader(raw))
		if e != nil {
			return nil, e
		}
		_, result := j.Append(domain.NewID(), "evidence_proposal", at, func(s evidence.Source) ([]byte, error) {
			return json.Marshal(map[string]any{"source_owner_id": s.Owner, "source_subkey": domain.U64(s.Subkey), "source_control_seq": domain.U64(s.Seq), "thread_key": domain.U64(key), "operation_id": f.Records[0].ID, "thread_seq": domain.U64(1), "thread_frame_sha256": domain.Hash(sha256.Sum256(raw)), "committed_at_ns": at, "retention_until_ns": domain.Time(domain.SixMonths(time.Unix(0, int64(at))).UnixNano()), "prepared_frame_base64": base64.StdEncoding.EncodeToString(raw), "capture": json.RawMessage(`{"fixture":false}`)})
		})
		return nil, result.Err
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestRejectedOriginalProductStartupAndRestart(t *testing.T) {
	cfg, r, info := postingRepositoryFixture(t)
	raw, at := agedRejectedFrame(t)
	key, e := r.ReserveThreadKey(t.Context(), info.ID, time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	appendRejectedProposal(t, r, info.ID, key, raw, at)
	r = reopenRejectedProduct(t, cfg, r)
	if n, e := r.SweepRequiredOriginals(t.Context()); e != nil || n != 1 {
		t.Fatal("second source day not completed", n, e)
	}
	assertRejectedProductStorage(t, r, info.ID, key, raw)
	assertRejectedReaderBoundary(t, r, info)
	r = reopenRejectedProduct(t, cfg, r)
	defer r.Close()
	assertRejectedProductStorage(t, r, info.ID, key, raw)
	if result := r.Post(t.Context(), info.ID, key, raw, []byte(`{"fixture":false}`)); result.Status != store.NotWritten {
		t.Fatal("old rejected operation reused", result)
	}
	assertNewPostingAfterRejectedCleanup(t, r, info.ID)
	if n, e := r.SweepRequiredOriginals(t.Context()); e != nil || n != 0 {
		t.Fatal(n, e)
	}
}

func assertRejectedProductStorage(t *testing.T, r *Repository, id domain.ID, key uint64, raw []byte) {
	t.Helper()
	site, _, e := r.requiredGCJob(time.Now())
	if e != nil || site.MinimumReader != 55 {
		t.Fatal(site.MinimumReader, e)
	}
	b := r.posting[id]
	value, e := b.worker.Submit(t.Context(), func() (any, error) { return rejectedProductReady(b, key) })
	if e != nil || !value.(bool) {
		t.Fatal(value, e)
	}
	if _, e = os.Stat(filepath.Join(b.threadsDir, strconv.FormatUint(key, 10))); !os.IsNotExist(e) {
		t.Fatal("unaccepted thread became public", e)
	}
	for name, data := range requiredStartupFiles(t, r.cfg.DataDir) {
		if bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(raw))) {
			t.Fatal("rejected body remains", name)
		}
	}
}

func assertRejectedReaderBoundary(t *testing.T, r *Repository, info BoardInfo) {
	t.Helper()
	site, _, e := r.requiredGCJob(time.Now())
	if e != nil {
		t.Fatal(e)
	}
	site.MinimumReader = 51
	seed, signing, e := readRetirementKey(r.cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	defer clear(signing)
	before := requiredStartupFiles(t, r.cfg.DataDir)
	if e = inspectRequiredBoardJournals(r.cfg, site, persistedBoard{info: info}, signing); e == nil {
		t.Fatal("24h format accepted under reader51")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, r.cfg.DataDir)) {
		t.Fatal("reader refusal changed storage")
	}
}

func reopenRejectedProduct(t *testing.T, cfg Config, r *Repository) *Repository {
	t.Helper()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	next, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	return next
}

func rejectedProductReady(b *postingBoard, key uint64) (any, error) {
	count, connections := 0, 0
	for _, j := range b.journals {
		retired, e := j.RequiredRetirements()
		if e != nil {
			return nil, e
		}
		count += len(retired)
		if app.RejectedConnectionPending(j) {
			connections++
		}
	}
	return count == 2 && connections == 1 && !b.threads[key].HasUnretiredRejections(), nil
}

func assertNewPostingAfterRejectedCleanup(t *testing.T, r *Repository, id domain.ID) {
	t.Helper()
	result := r.Post(t.Context(), id, 0, persistentFrame(t), []byte(`{"fixture":true}`))
	if result.Status != store.Durable {
		t.Fatal("new thread blocked by another key's rejected connection", result)
	}
}
