// 永続板でのキー予約・投稿・再送・所有排他をまとめて検査する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
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
	"testing"
	"time"
)

func postingCaptureFixture(b []byte) error {
	var v struct {
		Fixture bool `json:"fixture"`
	}
	return strictjson.Decode(b, &v)
}
func persistentFrame(t *testing.T) []byte {
	t.Helper()
	return persistentFrameAt(t, time.Now())
}

// persistentFrameAt は日付またぎを実時間より未来へ進めずに検査するための投稿fixture。
func persistentFrameAt(t *testing.T, at time.Time) []byte {
	t.Helper()
	raw, e := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(v.Operation)
	if e != nil {
		t.Fatal(e)
	}
	var create domain.Create
	if e = json.Unmarshal(op.Payload, &create); e != nil {
		t.Fatal(e)
	}
	now := domain.Time(at.UnixNano())
	op.Committed = now
	op.After.LastUserAt = now
	op.Dedup.Expires = now + 86400*1e9
	create.Created = now
	create.Expires = domain.Time(domain.SixMonths(time.Unix(0, int64(now))).UnixNano())
	create.Posts[0].Created = now
	op.Payload, _ = json.Marshal(create)
	raw, _ = json.Marshal(op)
	dat, e := hex.DecodeString(v.DAT)
	if e != nil {
		t.Fatal(e)
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: 1, Records: []store.Record{{ID: domain.NewID(), JSON: raw, DAT: dat}}})
	if e != nil {
		t.Fatal(e)
	}
	return frame
}
func TestRepositoryPostingAndCreateRetry(t *testing.T) {
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "保存試験"); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	b, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	frame := persistentFrame(t)
	first := repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"fixture":true}`))
	if first.Status != store.Durable || first.ThreadKey == 0 {
		t.Fatal(first)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	again := repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"fixture":true}`))
	if again.Status != store.Durable || !again.Duplicate || again.ThreadKey != first.ThreadKey {
		t.Fatal("new thread on retry", again)
	}
	snapshot, e := repo.Thread(context.Background(), b.ID, first.ThreadKey)
	if e != nil || snapshot == nil || snapshot.PostCount != 1 {
		t.Fatal(snapshot, e)
	}
	if _, e = OpenPostingRepository(cfg, postingCaptureFixture); e == nil {
		t.Fatal("second owner accepted")
	}
}

func postingRepositoryFixture(t *testing.T) (Config, *Repository, BoardInfo) {
	t.Helper()
	cfg := testConfig(t)
	if _, e := Initialize(cfg, "試験"); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	b, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return cfg, repo, b
}
func TestConcurrentCreateRetryReservesOneKey(t *testing.T) {
	_, repo, b := postingRepositoryFixture(t)
	frame := persistentFrame(t)
	results := make(chan RepositoryPostingResult, 16)
	for range 16 {
		go func() { results <- repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"fixture":true}`)) }()
	}
	var key uint64
	duplicates := 0
	for range 16 {
		r := <-results
		if r.Status != store.Durable {
			t.Fatal(r)
		}
		if key == 0 {
			key = r.ThreadKey
		}
		if key != r.ThreadKey {
			t.Fatal("retry allocated another key")
		}
		if r.Duplicate {
			duplicates++
		}
	}
	if duplicates != 15 {
		t.Fatal("duplicate count", duplicates)
	}
	next, e := repo.ReserveThreadKey(context.Background(), b.ID, time.Unix(0, 0))
	if e != nil || next != key+1 {
		t.Fatal("duplicate consumed reservation", next, e)
	}
}
func TestRepositoryPostingIsolationAndStop(t *testing.T) {
	_, repo, first := postingRepositoryFixture(t)
	second, e := repo.CreateBoard(context.Background(), "other", "別板")
	if e != nil {
		t.Fatal(e)
	}
	b := repo.posting[first.ID]
	now := time.Now()
	b.clock = func() time.Time { return now }
	if _, e = b.journal(now); e != nil {
		t.Fatal(e)
	}
	// 初回journal作成直前の保存先競合を起こし、保存不明を板全体へ伝播させる。
	path := filepath.Join(b.evidenceDir, now.UTC().Format("20060102"))
	if e = os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	frame := persistentFrame(t)
	result := repo.Post(context.Background(), first.ID, 0, frame, []byte(`{"fixture":true}`))
	if result.Status != store.Unknown {
		t.Fatal("uncertain creation not propagated", result)
	}
	if r := repo.Post(context.Background(), first.ID, 0, persistentFrame(t), []byte(`{"fixture":true}`)); r.Status != store.NotWritten {
		t.Fatal("stopped board wrote", r)
	}
	if _, e = repo.ReserveThreadKey(context.Background(), first.ID, now); e == nil {
		t.Fatal("stopped board reserved key")
	}
	good := repo.Post(context.Background(), second.ID, 0, frame, []byte(`{"fixture":true}`))
	if good.Status != store.Durable {
		t.Fatal("other board stopped", good)
	}
	snapshot, e := repo.Thread(context.Background(), first.ID, good.ThreadKey)
	if e != nil || snapshot != nil {
		t.Fatal("cross-board snapshot", snapshot, e)
	}
}
func TestRepositoryRejectsUnverifiedAndOutOfWatermark(t *testing.T) {
	cfg, repo, b := postingRepositoryFixture(t)
	r := repo.Post(context.Background(), b.ID, 0, persistentFrame(t), []byte(`{"fixture":true}`))
	if r.Status != store.Durable {
		t.Fatal(r)
	}
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := Check(cfg); e == nil {
		t.Fatal("schema-less check accepted capture")
	}
	if plain, e := OpenRepository(cfg); e == nil {
		plain.Close()
		t.Fatal("schema-less startup accepted capture")
	}
	root := filepath.Join(cfg.DataDir, "boards", b.ID.String(), "threads")
	if e := os.Rename(filepath.Join(root, fmt.Sprint(r.ThreadKey)), filepath.Join(root, fmt.Sprint(r.ThreadKey+1))); e != nil {
		t.Fatal(e)
	}
	if opened, e := OpenPostingRepository(cfg, postingCaptureFixture); e == nil {
		opened.Close()
		t.Fatal("unreserved key accepted")
	}
}
func TestRepositoryPostingPreflightDoesNotReserve(t *testing.T) {
	_, repo, b := postingRepositoryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	frame := persistentFrame(t)
	if r := repo.Post(ctx, b.ID, 0, frame, []byte(`{"fixture":true}`)); r.Status != store.NotWritten {
		t.Fatal(r)
	}
	if r := repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"password":"not-for-storage"}`)); r.Status != store.NotWritten {
		t.Fatal(r)
	}
	key, e := repo.ReserveThreadKey(context.Background(), b.ID, time.Unix(1, 0))
	if e != nil || key != 1 {
		t.Fatal("invalid input consumed key", key, e)
	}
}

func persistentReply(t *testing.T, frame []byte, now time.Time) []byte {
	t.Helper()
	f, _, e := store.ReadFrame(bytes.NewReader(frame))
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
	op.Type = "append"
	op.Revision = 2
	op.Versions.Thread = 1
	op.Committed = domain.Time(now.UnixNano())
	op.After.LastUserAt = op.Committed
	op.After.PostCount = 2
	op.After.UserCount = 2
	op.After.DATBytes *= 2
	op.Dedup.PostNumber = 2
	op.Dedup.Expires = op.Committed + 86400*1e9
	(*op.Dedup.RequestID)[0] ^= 1
	op.Dedup.Request[0] ^= 1
	post := create.Posts[0]
	post.Number = 2
	post.Created = op.Committed
	op.Payload, _ = json.Marshal(domain.Append{Posts: []domain.Post{post}})
	raw, _ := json.Marshal(op)
	result, e := store.EncodeFrame(store.Frame{FirstSeq: 2, Records: []store.Record{{ID: domain.NewID(), JSON: raw, DAT: f.Records[0].DAT}}})
	if e != nil {
		t.Fatal(e)
	}
	return result
}
func TestRepositoryPostingDayRotationAndReply(t *testing.T) {
	cfg, repo, b := postingRepositoryFixture(t)
	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	repo.posting[b.ID].clock = func() time.Time { return yesterday }
	frame := persistentFrameAt(t, yesterday)
	created := repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"fixture":true}`))
	if created.Status != store.Durable {
		t.Fatal(created)
	}
	tomorrow := time.Now().UTC()
	repo.posting[b.ID].clock = func() time.Time { return tomorrow }
	reply := persistentReply(t, frame, tomorrow)
	result := repo.Post(context.Background(), b.ID, created.ThreadKey, reply, []byte(`{"fixture":true}`))
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	days, e := postingNames(filepath.Join(cfg.DataDir, "evidence", b.ID.String()))
	if e != nil || len(days) != 2 {
		t.Fatal("day rotation", days, e)
	}
	repo, e = OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	snap, e := repo.Thread(context.Background(), b.ID, created.ThreadKey)
	if e != nil || snap == nil || snap.PostCount != 2 {
		t.Fatal(snap, e)
	}
	retry := repo.Post(context.Background(), b.ID, created.ThreadKey, reply, []byte(`{"fixture":true}`))
	if retry.Status != store.Durable || !retry.Duplicate {
		t.Fatal("reply retry", retry)
	}
}
func TestRepositoryCloseDrainsPosting(t *testing.T) {
	_, repo, b := postingRepositoryFixture(t)
	if e := repo.EnableThreadRetention(context.Background()); e != nil {
		t.Fatal(e)
	}
	expiryDone := repo.posting[b.ID].expiryDone
	if expiryDone == nil {
		t.Fatal("retention scheduler missing")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	repo.posting[b.ID].checkpoint = func(stage string) {
		if stage == "reservation" {
			close(entered)
			<-release
		}
	}
	frame := persistentFrame(t)
	result := make(chan RepositoryPostingResult, 1)
	go func() { result <- repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"fixture":true}`)) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- repo.Close() }()
	close(release)
	if got := <-result; got.Status != store.Durable {
		t.Fatal("started posting lost", got)
	}
	if e := <-closed; e != nil {
		t.Fatal(e)
	}
	select {
	case <-expiryDone:
	default:
		t.Fatal("retention scheduler survived Close")
	}
	if got := repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"fixture":true}`)); got.Status != store.NotWritten {
		t.Fatal("closed repository accepted", got)
	}
}

func TestCreateRetryConflictDoesNotReserve(t *testing.T) {
	_, repo, b := postingRepositoryFixture(t)
	frame := persistentFrame(t)
	first := repo.Post(context.Background(), b.ID, 0, frame, []byte(`{"fixture":true}`))
	if first.Status != store.Durable {
		t.Fatal(first)
	}
	f, _, e := store.ReadFrame(bytes.NewReader(frame))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	op.Dedup.Request[0] ^= 1
	f.Records[0].ID = domain.NewID()
	f.Records[0].JSON, _ = json.Marshal(op)
	changed, e := store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	result := repo.Post(context.Background(), b.ID, 0, changed, []byte(`{"fixture":true}`))
	if result.Status != store.NotWritten || result.Err == nil {
		t.Fatal("changed retry accepted", result)
	}
	next, e := repo.ReserveThreadKey(context.Background(), b.ID, time.Unix(0, 0))
	if e != nil || next != first.ThreadKey+1 {
		t.Fatal(next, e)
	}
}
func TestRepositoryRejectsConflictingRecoveredCreateRequests(t *testing.T) {
	cfg, repo, info := postingRepositoryFixture(t)
	frame := persistentFrame(t)
	first := repo.Post(context.Background(), info.ID, 0, frame, []byte(`{"fixture":true}`))
	if first.Status != store.Durable {
		t.Fatal(first)
	}
	// 以前の単一スレッドAPIで二重作成されたデータを作り、板復旧時の曖昧さを検査する。
	key, e := repo.ReserveThreadKey(context.Background(), info.ID, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	f, _, e := store.ReadFrame(bytes.NewReader(frame))
	if e != nil {
		t.Fatal(e)
	}
	f.Records[0].ID = domain.NewID()
	duplicate, e := store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	b := repo.posting[info.ID]
	journal, e := b.journal(time.Now())
	if e != nil {
		t.Fatal(e)
	}
	log, e := app.OpenPosting(b.threadsDir, b.owner, key, []*evidence.Journal{journal}, journal, domain.Time(time.Now().UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	result := log.Post(context.Background(), duplicate, []byte(`{"fixture":true}`), domain.Time(time.Now().UnixNano()))
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	if e = log.Close(); e != nil {
		t.Fatal(e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	opened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e == nil {
		opened.Close()
		t.Fatal("ambiguous retry restored")
	}
	if !errors.Is(e, app.ErrEvidenceGap) {
		t.Fatal(e)
	}
}
